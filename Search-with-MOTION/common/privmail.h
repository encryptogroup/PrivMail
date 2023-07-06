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

#pragma once

#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"
#include "utility/typedefs.h"

enum search_mode_enum {
  eNormal,
  eHidden,
  eBucket,
  eIndex,
  eError,
};

struct search_query {
  std::string keyword;  // Most likely not needed, but include here for completeness
  std::uint32_t bucket_size;
  std::string keyword_bucketed;
  std::string keyword_length_mask;
  std::string keyword_truncated;
};

struct bucket_block {
  std::uint32_t bucket_size;
  std::vector<std::string> words;
};

struct mail_structure {
  std::string subject;             // Most likely not needed, but include here for completeness
  std::string secret_share_block;  // Most likely not needed, but include here for completeness
  std::string secret_share_truncated_block;
  std::vector<bucket_block> buckets;
};

struct index_bucket {
  std::uint32_t bucket_size;
  std::vector<std::pair<std::string, std::string>> word_and_occurrence_strings;
};

struct search_index {
  std::uint32_t num_of_emails;
  std::vector<index_bucket> index_buckets;
};

struct query_input {
  std::uint32_t bucket_size;
  std::vector<encrypto::motion::ShareWrapper> search_keyword;
  std::vector<encrypto::motion::ShareWrapper> length_mask;  // E.g., if the length is 3, this is 1110 0000 000... in binary
};

struct bucket_input {
  std::uint32_t bucket_size;
  std::vector<std::vector<encrypto::motion::ShareWrapper>> words;
};

std::vector<encrypto::motion::ShareWrapper> PrivMailSearch(encrypto::motion::PartyPointer& party,
                                                           const std::vector<search_query>& search_queries,
                                                           const std::string& modifier_chain_share,
                                                           const std::vector<mail_structure>& mails,
                                                           const search_index& search_index,
                                                           const std::vector<std::uint32_t> bucket_scheme,
                                                           const search_mode_enum& search_mode);
