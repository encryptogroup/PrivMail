// MIT License
//
// Copyright (c) 2021 Raine Nieminen
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "privmail.h"

#include "algorithm/algorithm_description.h"
#include "algorithm/low_depth_reduce.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

static void debugMessage(const encrypto::motion::PartyPointer& party, const std::string message);

static std::vector<encrypto::motion::ShareWrapper> base64StringToInput(
    const encrypto::motion::PartyPointer& party, const std::string& input_string);

static std::vector<encrypto::motion::ShareWrapper> FromSharesToValue(
  const std::vector<std::vector<encrypto::motion::ShareWrapper>> shares);

static std::vector<encrypto::motion::ShareWrapper> splitTo1bitShareWrappers(
    const std::vector<encrypto::motion::ShareWrapper>& input);

static std::vector<encrypto::motion::SecureUnsignedInteger> concatenateTo8bitSecureUnsignedIntegers(
    const std::vector<encrypto::motion::ShareWrapper>& input,
    const encrypto::motion::ShareWrapper& full_zero);

static std::vector<query_input> getBucketedKeywordInput(
    encrypto::motion::PartyPointer& party, const std::vector<search_query>& search_queries);

static std::uint32_t getMinKeywordLength(const std::uint32_t bucket_size,
                                         const std::vector<std::uint32_t> bucket_scheme);

static encrypto::motion::ShareWrapper CreateChainingCircuit(
    const encrypto::motion::ShareWrapper& previous_search_result,
    const encrypto::motion::ShareWrapper& new_search_result,
    const encrypto::motion::ShareWrapper& OR_BIT,
    const encrypto::motion::ShareWrapper& NOT_BIT);

std::vector<encrypto::motion::ShareWrapper> PrivMailSearch(encrypto::motion::PartyPointer& party,
                                                           const std::vector<search_query>& search_queries,
                                                           const std::string& modifier_chain_share,
                                                           const std::vector<mail_structure>& mails,
                                                           const search_index& search_index,
                                                           const std::vector<std::uint32_t> bucket_scheme,
                                                           const search_mode_enum& search_mode) {
  // Create a ShareWrapper initialized with 0 (false)
  const encrypto::motion::ShareWrapper full_zero = party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
      encrypto::motion::BitVector<>(1, false), 0);

  // Decode and initialize the modifier_chain_share
  debugMessage(party, fmt::format("Modifier chain share: {}", modifier_chain_share));
  auto modifier_chain_input = base64StringToInput(party, modifier_chain_share);
  auto modifier_chain_share_input = splitTo1bitShareWrappers(modifier_chain_input);

  // Declare a vector for the final results
  std::vector<encrypto::motion::ShareWrapper> search_results;

  switch (search_mode) {
    case eNormal: {
      // Decode and initialize the search keywords
      std::vector<std::vector<encrypto::motion::ShareWrapper>> search_keywords;
      for (auto& search_query : search_queries) {
        debugMessage(party, fmt::format("Keyword: {} (no bucketing)", search_query.keyword_truncated));
        search_keywords.push_back(base64StringToInput(party, search_query.keyword_truncated));
      }
      assert(modifier_chain_share_input.size() >= 2 * search_keywords.size() - 1);

      // Decode and initialize the target text
      std::vector<std::vector<encrypto::motion::ShareWrapper>> target_texts;
      for (auto& mail : mails) {
        debugMessage(party, fmt::format("Target text: {}", mail.secret_share_truncated_block));
        target_texts.push_back(base64StringToInput(party, mail.secret_share_truncated_block));
      }

      // Resize the vector for the final results
      search_results.resize(target_texts.size());

      // Search with the keywords over the target texts
      for (std::size_t j = 0; j < search_keywords.size(); j++) {
        for (std::size_t i = 0; i < target_texts.size(); i++) {
          // Search over a single text with a single keyword
          auto search_keyword = search_keywords[j];
          auto target_text = target_texts[i];

          std::int32_t num_of_positions = target_text.size() - search_keyword.size() + 1;

          if (num_of_positions < 1) {
            // Nothing to compare, most likely the target text is very short

            // Chain the zero result (false) for each keyword and take NOT if needed
            if (j == 0) {
              // For the first keyword we have nothing to chain
              search_results[i] = full_zero ^ modifier_chain_share_input[0];  // NOT if XORed with 1
            } else {
              search_results[i] = CreateChainingCircuit(search_results[i],
                                                        full_zero,
                                                        modifier_chain_share_input[2 * j - 1],
                                                        modifier_chain_share_input[2 * j]);
            }
            continue;
          }

          std::vector<std::vector<encrypto::motion::ShareWrapper>> xnor_splitted_per_position;
          for (int32_t k = 0; k < num_of_positions; k++) {
            // Compare the keyword to the text at each position

            std::vector<encrypto::motion::ShareWrapper> splitted_keyword;
            std::vector<encrypto::motion::ShareWrapper> splitted_text;
            for (std::size_t c = 0; c < search_keyword.size(); c++) {
              // Truncate the length of each character
              const int character_bitlen = 6;  // Follows from the special PrivMail encoding

              // Collect the truncated characters
              auto splitted_keyword_character = search_keyword[c].Split();
              splitted_keyword.insert(splitted_keyword.end(),
                                      splitted_keyword_character.begin(),
                                      splitted_keyword_character.begin() + character_bitlen);

              auto splitted_text_character = target_text[c + k].Split();
              splitted_text.insert(splitted_text.end(),
                                  splitted_text_character.begin(),
                                  splitted_text_character.begin() + character_bitlen);
            }
            // Concatenate truncated characters and compare the long strings
            auto a = encrypto::motion::ShareWrapper::Concatenate(splitted_keyword);
            auto b = encrypto::motion::ShareWrapper::Concatenate(splitted_text);
            auto xnor_ab = ~(a ^ b);  // XNOR
            xnor_splitted_per_position.push_back(xnor_ab.Split());
          }

          // Combine the bits (basically transfers {{a,b},{c,d}} to {{a,c},{b,d}})
          std::vector<std::vector<encrypto::motion::ShareWrapper>> xnor_combined(xnor_splitted_per_position[0].size());
          for (auto& xnor_position_splitted : xnor_splitted_per_position) {
            for (std::size_t i = 0; i < xnor_position_splitted.size(); i++) {
              xnor_combined[i].push_back(xnor_position_splitted[i]);
            }
          }

          // Concatenate each combined string
          std::vector<encrypto::motion::ShareWrapper> xnor_concatenated;
          for (auto& xnor_comb : xnor_combined) {
            xnor_concatenated.push_back(encrypto::motion::ShareWrapper::Simdify(xnor_comb));
          }

          // Do the AND operations now in parallel
          encrypto::motion::ShareWrapper result_bits = LowDepthReduce(xnor_concatenated, std::bit_and<>());

          // Finally, use OR tree to get the final answer of whether any of the comparisons was a match
          auto search_result_per_email =  LowDepthReduce(result_bits.Split(), std::bit_or<>());

          assert(search_result_per_email->GetBitLength() == 1);

          // Chain the results for each keyword and take NOT if needed
          if (j == 0) {
            // For the first keyword we have nothing to chain
            search_results[i] = search_result_per_email ^ modifier_chain_share_input[0];  // NOT if XORed with 1
          } else {
            search_results[i] = CreateChainingCircuit(search_results[i],
                                                      search_result_per_email,
                                                      modifier_chain_share_input[2 * j - 1],
                                                      modifier_chain_share_input[2 * j]);
          }
        }
      }

      break;
    }
    case eHidden: {
      // Decode and initialize the search keywords (bucketed versions)
      std::vector<query_input> search_keywords = getBucketedKeywordInput(party, search_queries);
      assert(modifier_chain_share_input.size() >= 2 * search_keywords.size() - 1);

      // Decode and initialize the target text
      std::vector<std::vector<encrypto::motion::ShareWrapper>> target_texts;
      for (auto& mail : mails) {
        debugMessage(party, fmt::format("Target text: {}", mail.secret_share_truncated_block));
        target_texts.push_back(base64StringToInput(party, mail.secret_share_truncated_block));
      }

      // Resize the vector for the final results
      search_results.resize(target_texts.size());

      // Search with the keywords over the target texts
      for (std::size_t j = 0; j < search_keywords.size(); j++) {
        // Search over the target texts with a single keyword (bucketed versions)
        auto search_keyword = search_keywords[j];

        // Determine the minimum length of the keyword
        std::uint32_t min_keyword_length = getMinKeywordLength(search_keyword.bucket_size, bucket_scheme);

        for (std::size_t i = 0; i < target_texts.size(); i++) {
          // Search over a single text with a single keyword (bucketed versions)
          auto target_text = target_texts[i];

          // In the first pass, just compute the first layer of each character comparison, i.e., ~(a^b)
          std::vector<std::vector<encrypto::motion::ShareWrapper>> all_xnors;
          std::vector<encrypto::motion::ShareWrapper> all_length_mask_bits;

          std::int32_t num_of_positions = target_text.size() - min_keyword_length + 1;

          if (num_of_positions < 1) {
            // Nothing to compare, most likely the target text is very short

            // Chain the zero result (false) for each keyword and take NOT if needed
            if (j == 0) {
              // For the first keyword we have nothing to chain
              search_results[i] = full_zero ^ modifier_chain_share_input[0];  // NOT if XORed with 1
            } else {
              search_results[i] = CreateChainingCircuit(search_results[i],
                                                        full_zero,
                                                        modifier_chain_share_input[2 * j - 1],
                                                        modifier_chain_share_input[2 * j]);
            }
            continue;
          }

          for (int32_t text_position = 0; text_position < num_of_positions; text_position++) {
            std::vector<std::vector<encrypto::motion::ShareWrapper>> comparison_result;
            for (std::size_t c = 0; c < search_keyword.search_keyword.size(); c++) {

              // Truncate the length of each character
              const int character_bitlen = 6;  // Follows from the special PrivMail encoding

              if ((c + text_position) >= target_text.size()) {
                // Instead of breaking here, append with 1s
                std::vector<encrypto::motion::ShareWrapper> full_zero_split(character_bitlen, ~full_zero);
                comparison_result.push_back(full_zero_split);
                all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
                continue;
              }

              auto splitted_keyword_character = search_keyword.search_keyword[c].Split();
              auto truncated_keyword_character = encrypto::motion::ShareWrapper::Concatenate(
                  splitted_keyword_character.begin(), splitted_keyword_character.begin() + character_bitlen);

              auto splitted_text_character = target_text[c + text_position].Split();
              auto truncated_text_character = encrypto::motion::ShareWrapper::Concatenate(
                  splitted_text_character.begin(), splitted_text_character.begin() + character_bitlen);

              // Compare the truncated character from keyword and target text
              auto not_xor_a_b = ~(truncated_keyword_character^truncated_text_character);
              comparison_result.push_back(not_xor_a_b.Split());     // Split each ~(a^b)

              all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
            }
            all_xnors.insert(all_xnors.end(), comparison_result.begin(), comparison_result.end());
          }

          // Combine the bits (basically a zip operation: [[a,b],[c,d]] to [[a,c],[b,d]])
          std::vector<std::vector<encrypto::motion::ShareWrapper>> xor_combined(all_xnors[0].size());
          for (auto& xor_position_splitted : all_xnors) {
            for (std::size_t i = 0; i < xor_position_splitted.size(); i++) {
              xor_combined[i].push_back(xor_position_splitted[i]);
            }
          }

          // Concatenate each combined string
          std::vector<encrypto::motion::ShareWrapper> xor_simd;
          for (auto& xor_comb : xor_combined) {
            xor_simd.push_back(encrypto::motion::ShareWrapper::Simdify(xor_comb));
          }

          // Do the AND operations now in parallel
          encrypto::motion::ShareWrapper result_bits = LowDepthReduce(xor_simd, std::bit_and<>());

          // Apply the length mask bits in parallel
          auto result_after_length_mask = ( encrypto::motion::ShareWrapper::Simdify(result_bits.Split()) |
                                            encrypto::motion::ShareWrapper::Simdify(all_length_mask_bits) ).Unsimdify();

          // Do the character tree also in parallel
          std::vector<std::vector<encrypto::motion::ShareWrapper>> results_combined(search_keyword.search_keyword.size());

          // Combine the bits (basically a zip operation: [a,b,c,d] to [[a,c],[b,d]])
          for (std::uint32_t res_index = 0; res_index < result_after_length_mask.size(); res_index++) {
            int res_comb_index = res_index % search_keyword.search_keyword.size();
            results_combined[res_comb_index].push_back(result_after_length_mask[res_index]);
          }

          // Concatenate each combined string
          std::vector<encrypto::motion::ShareWrapper> res_concat;
          for (auto& res_comb : results_combined) {
            res_concat.push_back(encrypto::motion::ShareWrapper::Simdify(res_comb));
          }

          // Do the AND operations now in parallel
          encrypto::motion::ShareWrapper comparison_res_bits = LowDepthReduce(res_concat, std::bit_and<>());
          auto comparison_results_split = comparison_res_bits.Unsimdify();

          auto search_result_per_email = LowDepthReduceSIMD(comparison_results_split, std::bit_or<>());

          // Chain the results for each keyword and take NOT if needed
          if (j == 0) {
            // For the first keyword we have nothing to chain
            search_results[i] = search_result_per_email ^ modifier_chain_share_input[0];  // NOT if XORed with 1
          } else {
            search_results[i] = CreateChainingCircuit(search_results[i],
                                                      search_result_per_email,
                                                      modifier_chain_share_input[2 * j - 1],
                                                      modifier_chain_share_input[2 * j]);
          }
        }
      }
      break;
    }
    case eBucket: {
      // Decode and initialize the search keywords (bucketed versions)
      std::vector<query_input> search_keywords = getBucketedKeywordInput(party, search_queries);
      assert(modifier_chain_share_input.size() >= 2 * search_keywords.size() - 1);

      // Decode and initialize the buckets for each mail
      std::vector<std::vector<bucket_input>> target_texts;
      for (auto& mail : mails) {
        std::vector<bucket_input> buckets;
        for (auto& bucket : mail.buckets) {
          bucket_input target_bucket;
          target_bucket.bucket_size = bucket.bucket_size;
          for (auto& word : bucket.words) {
            debugMessage(party, fmt::format("Target word: {} (bucket size: {})", word, bucket.bucket_size));
            target_bucket.words.push_back(base64StringToInput(party, word));
          }
          buckets.push_back(target_bucket);
        }
        target_texts.push_back(buckets);
      }

      // Resize the vector for the final results
      search_results.resize(target_texts.size());

      // Search with the keywords over the target texts (bucketed versions)
      for (std::size_t j = 0; j < search_keywords.size(); j++) {
        // Search over the target texts with a single keyword (bucketed versions)
        auto search_keyword = search_keywords[j];

        // Determine the minimum length of the keyword
        std::uint32_t min_keyword_length = getMinKeywordLength(search_keyword.bucket_size, bucket_scheme);

        for (std::size_t i = 0; i < target_texts.size(); i++) {
          // Search over a single text with a single keyword (bucketed versions)
          auto target_text = target_texts[i];

          // In the first pass, just compute the first layer of each character comparison, i.e., ~(a^b)
          std::vector<std::vector<encrypto::motion::ShareWrapper>> all_xnors;
          std::vector<encrypto::motion::ShareWrapper> all_length_mask_bits;

          for (auto& target_bucket : target_text) {
            if (target_bucket.bucket_size < search_keyword.bucket_size) continue;

            for (auto& word : target_bucket.words) {

              std::int32_t num_of_positions = word.size() - min_keyword_length + 1;

              for (int32_t text_position = 0; text_position < num_of_positions; text_position++) {
                std::vector<std::vector<encrypto::motion::ShareWrapper>> comparison_result;
                for (std::size_t c = 0; c < search_keyword.search_keyword.size(); c++) {

                  // Truncate the length of each character
                  const int character_bitlen = 6;  // Follows from the special PrivMail encoding

                  if ((c + text_position) >= word.size()) {
                    // Instead of breaking here, append with 1s
                    std::vector<encrypto::motion::ShareWrapper> full_zero_split(character_bitlen, ~full_zero);
                    comparison_result.push_back(full_zero_split);
                    all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
                    continue;
                  }

                  auto splitted_keyword_character = search_keyword.search_keyword[c].Split();
                  auto truncated_keyword_character = encrypto::motion::ShareWrapper::Concatenate(
                      splitted_keyword_character.begin(), splitted_keyword_character.begin() + character_bitlen);

                  auto splitted_text_character = word[c + text_position].Split();
                  auto truncated_text_character = encrypto::motion::ShareWrapper::Concatenate(
                      splitted_text_character.begin(), splitted_text_character.begin() + character_bitlen);

                  // Compare the truncated character from keyword and target text
                  auto not_xor_a_b = ~(truncated_keyword_character^truncated_text_character);
                  comparison_result.push_back(not_xor_a_b.Split());     // Split each ~(a^b)

                  all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
                }
                all_xnors.insert(all_xnors.end(), comparison_result.begin(), comparison_result.end());
              }
            }
          }

          if (all_xnors.size() == 0) {
            // No available buckets at all (most likely because the keyword was very long)

            // Chain the zero result (false) for each keyword and take NOT if needed
            if (j == 0) {
              // For the first keyword we have nothing to chain
              search_results[i] = full_zero ^ modifier_chain_share_input[0];  // NOT if XORed with 1
            } else {
              search_results[i] = CreateChainingCircuit(search_results[i],
                                                        full_zero,
                                                        modifier_chain_share_input[2 * j - 1],
                                                        modifier_chain_share_input[2 * j]);
            }
            continue;
          }

          // Combine the bits (basically a zip operation: [[a,b],[c,d]] to [[a,c],[b,d]])
          std::vector<std::vector<encrypto::motion::ShareWrapper>> xor_combined(all_xnors[0].size());
          for (auto& xor_position_splitted : all_xnors) {
            for (std::size_t i = 0; i < xor_position_splitted.size(); i++) {
              xor_combined[i].push_back(xor_position_splitted[i]);
            }
          }

          // Concatenate each combined string
          std::vector<encrypto::motion::ShareWrapper> xor_simd;
          for (auto& xor_comb : xor_combined) {
            xor_simd.push_back(encrypto::motion::ShareWrapper::Simdify(xor_comb));
          }

          // Do the AND operations now in parallel
          encrypto::motion::ShareWrapper result_bits = LowDepthReduce(xor_simd, std::bit_and<>());

          // Apply the length mask bits in parallel
          auto result_after_length_mask = ( encrypto::motion::ShareWrapper::Simdify(result_bits.Split()) |
                                            encrypto::motion::ShareWrapper::Simdify(all_length_mask_bits) ).Unsimdify();

          // Do the character tree also in parallel
          std::vector<std::vector<encrypto::motion::ShareWrapper>> results_combined(search_keyword.search_keyword.size());

          // Combine the bits (basically a zip operation: [a,b,c,d] to [[a,c],[b,d]])
          for (std::uint32_t res_index = 0; res_index < result_after_length_mask.size(); res_index++) {
            int res_comb_index = res_index % search_keyword.search_keyword.size();
            results_combined[res_comb_index].push_back(result_after_length_mask[res_index]);
          }

          // Concatenate each combined string
          std::vector<encrypto::motion::ShareWrapper> res_concat;
          for (auto& res_comb : results_combined) {
            res_concat.push_back(encrypto::motion::ShareWrapper::Simdify(res_comb));
          }

          // Do the AND operations now in parallel
          encrypto::motion::ShareWrapper comparison_res_bits = LowDepthReduce(res_concat, std::bit_and<>());
          auto comparison_results_split = comparison_res_bits.Unsimdify();

          int counter = 0;
          // In the second pass, do the rest of the AND/OR trees to get the result
          std::vector<encrypto::motion::ShareWrapper> search_results_per_bucket;
          for (auto& target_bucket : target_text) {
            if (target_bucket.bucket_size < search_keyword.bucket_size) continue;

            std::vector<encrypto::motion::ShareWrapper> search_results_per_word;
            for (auto& word : target_bucket.words) {
              std::int32_t num_of_positions = word.size() - min_keyword_length + 1;

              std::vector<encrypto::motion::ShareWrapper> search_results_per_position;
              for (int32_t text_position = 0; text_position < num_of_positions; text_position++) {
                search_results_per_position.push_back(comparison_results_split[counter]);
                counter++;
              }

              // Finally, use OR tree to get the final answer of whether any of the comparisons was a match
              auto search_result_of_word = LowDepthReduceSIMD(search_results_per_position, std::bit_or<>());

              assert(search_result_of_word->GetBitLength() == 1);
              search_results_per_word.push_back(search_result_of_word);
            }
            search_results_per_bucket.push_back(
                LowDepthReduceSIMD(search_results_per_word, std::bit_or<>()));
          }

          auto search_result_per_email = LowDepthReduceSIMD(search_results_per_bucket, std::bit_or<>());

          // Chain the results for each keyword and take NOT if needed
          if (j == 0) {
            // For the first keyword we have nothing to chain
            search_results[i] = search_result_per_email ^ modifier_chain_share_input[0];  // NOT if XORed with 1
          } else {
            search_results[i] = CreateChainingCircuit(search_results[i],
                                                      search_result_per_email,
                                                      modifier_chain_share_input[2 * j - 1],
                                                      modifier_chain_share_input[2 * j]);
          }
        }
      }

      break;
    }
    case eIndex: {
      // Decode and initialize the search keywords (bucketed versions)
      std::vector<query_input> search_keywords = getBucketedKeywordInput(party, search_queries);
      assert(modifier_chain_share_input.size() >= 2 * search_keywords.size() - 1);


      // Decode and initialize the buckets for the search index
      std::uint32_t total_number_words = 0;
      std::vector<bucket_input> buckets;
      for (auto& bucket : search_index.index_buckets) {
        bucket_input target_bucket;
        target_bucket.bucket_size = bucket.bucket_size;
        for (auto& word_and_occurrence_string : bucket.word_and_occurrence_strings) {
          auto& word = word_and_occurrence_string.first;
          debugMessage(party, fmt::format("Target word: {} (bucket size: {})", word, bucket.bucket_size));
          target_bucket.words.push_back(base64StringToInput(party, word));
        }
        buckets.push_back(target_bucket);
        total_number_words += bucket.word_and_occurrence_strings.size();
      }

      // Resize the vector for the final results
      search_results.resize(total_number_words);

      // Search with the keywords over the target texts (bucketed versions)
      for (std::size_t j = 0; j < search_keywords.size(); j++) {
        // Search over the target texts with a single keyword (bucketed versions)
        auto search_keyword = search_keywords[j];

        // Determine the minimum length of the keyword
        std::uint32_t min_keyword_length = getMinKeywordLength(search_keyword.bucket_size, bucket_scheme);

        // Search over a single bucket with a single keyword (bucketed versions)
        std::vector<encrypto::motion::ShareWrapper> search_results_per_keyword;

        // In the first pass, just compute the first layer of each character comparison, i.e., ~(a^b)
        std::vector<std::vector<encrypto::motion::ShareWrapper>> all_xnors;
        std::vector<encrypto::motion::ShareWrapper> all_length_mask_bits;

        for (auto& target_bucket : buckets) {
          for (auto& word : target_bucket.words) {
            // Search over each bucket, skip if the target bucket is too small (i.e., impossible to match the keyword)
            if (target_bucket.bucket_size < search_keyword.bucket_size) {
              search_results_per_keyword.push_back(full_zero);
              continue;
            }

            std::int32_t num_of_positions = word.size() - min_keyword_length + 1;

            for (int32_t text_position = 0; text_position < num_of_positions; text_position++) {
              std::vector<std::vector<encrypto::motion::ShareWrapper>> comparison_result;
              for (std::size_t c = 0; c < search_keyword.search_keyword.size(); c++) {

                // Truncate the length of each character
                const int character_bitlen = 6;  // Follows from the special PrivMail encoding

                if ((c + text_position) >= word.size()) {
                  // Instead of breaking here, append with 1s
                  std::vector<encrypto::motion::ShareWrapper> full_zero_split(character_bitlen, ~full_zero);
                  comparison_result.push_back(full_zero_split);
                  all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
                  continue;
                }

                auto splitted_keyword_character = search_keyword.search_keyword[c].Split();
                auto truncated_keyword_character = encrypto::motion::ShareWrapper::Concatenate(
                    splitted_keyword_character.begin(), splitted_keyword_character.begin() + character_bitlen);

                auto splitted_text_character = word[c + text_position].Split();
                auto truncated_text_character = encrypto::motion::ShareWrapper::Concatenate(
                    splitted_text_character.begin(), splitted_text_character.begin() + character_bitlen);

                // Compare the truncated character from keyword and target text
                auto not_xor_a_b = ~(truncated_keyword_character^truncated_text_character);
                comparison_result.push_back(not_xor_a_b.Split());     // Split each ~(a^b)

                all_length_mask_bits.push_back(~search_keyword.length_mask[c]);
              }
              all_xnors.insert(all_xnors.end(), comparison_result.begin(), comparison_result.end());
            }
          }
        }

        // Combine the bits (basically a zip operation: [[a,b],[c,d]] to [[a,c],[b,d]])
        std::vector<std::vector<encrypto::motion::ShareWrapper>> xor_combined(all_xnors[0].size());
        for (auto& xor_position_splitted : all_xnors) {
          for (std::size_t i = 0; i < xor_position_splitted.size(); i++) {
            xor_combined[i].push_back(xor_position_splitted[i]);
          }
        }

        // Concatenate each combined string
        std::vector<encrypto::motion::ShareWrapper> xor_simd;
        for (auto& xor_comb : xor_combined) {
          xor_simd.push_back(encrypto::motion::ShareWrapper::Simdify(xor_comb));
        }

        // Do the AND operations now in parallel
        encrypto::motion::ShareWrapper result_bits = LowDepthReduce(xor_simd, std::bit_and<>());

        // Apply the length mask bits in parallel
        auto result_after_length_mask = ( encrypto::motion::ShareWrapper::Simdify(result_bits.Split()) |
                                          encrypto::motion::ShareWrapper::Simdify(all_length_mask_bits) ).Unsimdify();

        // Do the character tree also in parallel
        std::vector<std::vector<encrypto::motion::ShareWrapper>> results_combined(search_keyword.search_keyword.size());

        // Combine the bits (basically a zip operation: [a,b,c,d] to [[a,c],[b,d]])
        for (std::uint32_t res_index = 0; res_index < result_after_length_mask.size(); res_index++) {
          int res_comb_index = res_index % search_keyword.search_keyword.size();
          results_combined[res_comb_index].push_back(result_after_length_mask[res_index]);
        }

        // Concatenate each combined string
        std::vector<encrypto::motion::ShareWrapper> res_concat;
        for (auto& res_comb : results_combined) {
          res_concat.push_back(encrypto::motion::ShareWrapper::Simdify(res_comb));
        }

        // Do the AND operations now in parallel
        encrypto::motion::ShareWrapper comparison_res_bits = LowDepthReduce(res_concat, std::bit_and<>());
        auto comparison_results_split = comparison_res_bits.Unsimdify();

        int counter = 0;
        // In the second pass, do the rest of the AND/OR trees to get the result
        std::vector<encrypto::motion::ShareWrapper> search_results_per_bucket;
        for (auto& target_bucket : buckets) {
          if (target_bucket.bucket_size < search_keyword.bucket_size) continue;

          std::vector<encrypto::motion::ShareWrapper> search_results_per_word;
          for (auto& word : target_bucket.words) {
            std::int32_t num_of_positions = word.size() - min_keyword_length + 1;

            std::vector<encrypto::motion::ShareWrapper> search_results_per_position;
            for (int32_t text_position = 0; text_position < num_of_positions; text_position++) {
              search_results_per_position.push_back(comparison_results_split[counter]);
              counter++;
            }

            // Finally, use OR tree to get the final answer of whether any of the comparisons was a match
            auto search_result_of_word = LowDepthReduceSIMD(search_results_per_position, std::bit_or<>());

            assert(search_result_of_word->GetBitLength() == 1);
            search_results_per_word.push_back(search_result_of_word);
          }
          search_results_per_keyword.insert(search_results_per_keyword.end(),
                                            search_results_per_word.begin(),
                                            search_results_per_word.end());
        }
        assert(search_results_per_keyword.size() == search_results.size());

        for (std::size_t i = 0; i < search_results.size(); i++) {
          // Chain the results for each keyword and take NOT if needed
          if (j == 0) {
            // For the first keyword we have nothing to chain
            search_results[i] = search_results_per_keyword[i] ^ modifier_chain_share_input[0];  // NOT if XORed with 1
          } else {
            search_results[i] = CreateChainingCircuit(search_results[i],
                                                      search_results_per_keyword[i],
                                                      modifier_chain_share_input[2 * j - 1],
                                                      modifier_chain_share_input[2 * j]);
          }
        }
      }

      break;
    }
    default: {
      throw std::invalid_argument("Invalid Search Mode");
    }
  }

  /** The search is DONE! Each ShareWrapper in search_results is a single bit
      denoting if the search criteria was fulfilled for that email. **/

  // Set the output gates (NOTE: in practice the parties wouldn't get the outputs in clear!)
  //for (auto& search_result : search_results) search_result = search_result.Out();

  party->Run();
  party->Finish();

  return search_results;
}

static void debugMessage(const encrypto::motion::PartyPointer& party, const std::string message) {
  // Uncomment below to print the messages in terminal
  //std::cout << "(party " << party->GetConfiguration()->GetMyId() << "): " << message << std::endl;
  party->GetLogger()->LogDebug(fmt::format("PrivMail_Logger {}", message));
}

static std::vector<std::uint8_t> simple_base64_decoder(const std::string& data) {
  const static std::string base64_chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";
  std::vector<std::uint8_t> decoded;
  std::uint32_t bit_stream = 0;
  std::uint32_t counter = 0;
  std::uint32_t offset = 0;
  for (unsigned char c : data) {
    auto num_val = base64_chars.find(c);
    if (num_val != std::string::npos) {
      offset = 18 - counter % 4 * 6;
      bit_stream += num_val << offset;
      if (offset == 12) {
        decoded.push_back(bit_stream >> 16 & 0xff);
      }
      if (offset == 6) {
        decoded.push_back(bit_stream >> 8 & 0xff);
      }
      if (offset == 0) {
        decoded.push_back(bit_stream & 0xff);
        bit_stream = 0;
      }
    } else if (c != '=') {
      return std::vector<std::uint8_t>();
    }
    counter++;
  }
  return decoded;
}

static std::vector<encrypto::motion::ShareWrapper> base64StringToInput(
    const encrypto::motion::PartyPointer& party, const std::string& input_string) {

  auto N = party->GetConfiguration()->GetNumOfParties();

  std::vector<std::vector<encrypto::motion::ShareWrapper>> input_shares;
  for (std::size_t i = 0; i < N; i++) {

    std::vector<encrypto::motion::ShareWrapper> input_vector;
    for (auto& one_byte : simple_base64_decoder(input_string)) {
      input_vector.push_back(party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(
          encrypto::motion::ToInput(one_byte), i));
    }

    input_shares.push_back(input_vector);
  }
  return FromSharesToValue(input_shares);
}

static std::vector<encrypto::motion::ShareWrapper> FromSharesToValue(
  const std::vector<std::vector<encrypto::motion::ShareWrapper>> shares) {
  std::vector<encrypto::motion::ShareWrapper> value;
  for (std::size_t i = 0; i < shares.size(); i++) {
    if (i == 0) {
      for (std::size_t j = 0; j < shares[0].size(); j++) {
        value.push_back(shares[0][j]);
      }
    } else {
      for (std::size_t j = 0; j < shares[i].size(); j++) {
        value[j] ^= shares[i][j];
      }
    }
  }
  return value;
}

static std::vector<encrypto::motion::ShareWrapper> splitTo1bitShareWrappers(
    const std::vector<encrypto::motion::ShareWrapper>& input) {
  // Split 8-bit ShareWrappers a vector of 1-bit ShareWrappers
  std::vector<encrypto::motion::ShareWrapper> output;
  for (auto& input_byte : input) {
    assert(input_byte->GetBitLength() == 8);  // NOTE: This might work correctly for other bitlengths as well
    auto byte_split = input_byte.Split();
    std::reverse(byte_split.begin(), byte_split.end());
    output.insert(output.end(), byte_split.begin(), byte_split.end());
  }
  return output;
}

static std::vector<encrypto::motion::SecureUnsignedInteger> concatenateTo8bitSecureUnsignedIntegers(
    const std::vector<encrypto::motion::ShareWrapper>& input,
    const encrypto::motion::ShareWrapper& full_zero) {
  std::vector<encrypto::motion::SecureUnsignedInteger> output;
  std::vector<encrypto::motion::ShareWrapper> tmp;

  // Concatenate 1-bit ShareWrappers to 8-bit SecureUnsignedIntegers
  for (auto& input_bit : input) {
    assert(input_bit->GetBitLength() == 1);
    tmp.push_back(input_bit);
    if (tmp.size() == 8) {
      std::reverse(tmp.begin(), tmp.end());
      output.push_back(encrypto::motion::ShareWrapper::Concatenate(tmp));
      tmp.clear();
    }
  }

  // At the end, append the last item with zeros and add to the output
  if (!tmp.empty()) {
    while (tmp.size() < 8) {
      tmp.push_back(full_zero);  // Append with zeros
    }
    std::reverse(tmp.begin(), tmp.end());
    output.push_back(encrypto::motion::ShareWrapper::Concatenate(tmp));
    tmp.clear();
  }

  return output;
}

static std::vector<query_input> getBucketedKeywordInput(
    encrypto::motion::PartyPointer& party, const std::vector<search_query>& search_queries) {
  std::vector<query_input> search_keywords;
  for (auto& search_query : search_queries) {
    query_input bucket_search_keyword;

    debugMessage(party, fmt::format("Keyword: {} (bucket size: {})", search_query.keyword_bucketed,
                                    search_query.bucket_size));
    bucket_search_keyword.bucket_size = search_query.bucket_size;
    bucket_search_keyword.search_keyword = base64StringToInput(party, search_query.keyword_bucketed);

    debugMessage(party, fmt::format("Length mask: {}", search_query.keyword_length_mask));
    auto length_mask_input = base64StringToInput(party, search_query.keyword_length_mask);
    bucket_search_keyword.length_mask = splitTo1bitShareWrappers(length_mask_input);

    assert(bucket_search_keyword.bucket_size == bucket_search_keyword.search_keyword.size());
    search_keywords.push_back(bucket_search_keyword);
  }
  return search_keywords;
}

static std::uint32_t getMinKeywordLength(const std::uint32_t bucket_size,
                                         const std::vector<std::uint32_t> bucket_scheme) {
  auto it = std::find(bucket_scheme.begin(), bucket_scheme.end(), bucket_size);
  if (it != bucket_scheme.end()) {
    if (it != bucket_scheme.begin()) {
      return *(it - 1) + 1;
    } else {
      return 1;
    }
  } else {
    throw std::invalid_argument("Search keyword has invalid bucket size!");
  }
}

static encrypto::motion::ShareWrapper CreateChainingCircuit(
    const encrypto::motion::ShareWrapper& previous_search_result,
    const encrypto::motion::ShareWrapper& new_search_result,
    const encrypto::motion::ShareWrapper& OR_BIT,
    const encrypto::motion::ShareWrapper& NOT_BIT) {
  assert(previous_search_result->GetBitLength() == 1);
  assert(new_search_result->GetBitLength() == 1);
  assert(OR_BIT->GetBitLength() == 1);   // Makes the AND operation below to OR if 1
  assert(NOT_BIT->GetBitLength() == 1);  // NOT operation if 1

  auto search_result =
      ((previous_search_result ^ OR_BIT) & ((new_search_result ^ NOT_BIT) ^ OR_BIT)) ^ OR_BIT;
  return search_result;
}
