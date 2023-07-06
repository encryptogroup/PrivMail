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

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <regex>

#include <fmt/format.h>
#include <yaml-cpp/yaml.h>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>

#include "base/party.h"
#include "common/privmail.h"
#include "communication/communication_layer.h"
#include "communication/tcp_transport.h"
#include "statistics/analysis.h"

namespace program_options = boost::program_options;

bool CheckPartyArgumentSyntax(const std::string& party_argument);

std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]);

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options);

search_mode_enum GetSearchMode(const std::string& in_string);

std::vector<search_query> SearchQueriesFromFile(const YAML::Node& search_query_yaml_file);

std::vector<mail_structure> MailsFromDirectory(const std::string& mail_directory_path, const std::vector<std::uint32_t> bucket_scheme);

search_index IndexFromFile(const std::string& index_file_path);

std::uint32_t GetCharacterLengthFromBase64(const std::string& base64_string);

int main(int ac, char* av[]) {
  auto [user_options, help_flag] = ParseProgramOptions(ac, av);
  // if help flag is set - print allowed command line arguments and exit
  if (help_flag) return EXIT_SUCCESS;

  encrypto::motion::AccumulatedRunTimeStatistics accumulated_runtime_statistics;
  encrypto::motion::AccumulatedCommunicationStatistics accumulated_communication_statistics;

  std::string search_mode_string = user_options["search-mode"].as<std::string>();
  search_mode_enum search_mode = GetSearchMode(search_mode_string);

  std::string search_query_file_path = user_options["query-file-path"].as<std::string>();
  YAML::Node search_query_yaml_file = YAML::LoadFile(search_query_file_path);

  // Read the modifier_chain_share
  std::string modifier_chain_share = search_query_yaml_file["modifier_chain_share"].as<std::string>();

  // Read the bucket_scheme
  std::vector<std::uint32_t> bucket_scheme = search_query_yaml_file["bucket_scheme"].as<std::vector<std::uint32_t>>();

  // Read the queries
  std::vector<search_query> search_queries = SearchQueriesFromFile(search_query_yaml_file);

  // Read the mails
  std::vector<mail_structure> mails;
  if (user_options.count("mail-dir-path")) {
    std::string mail_directory_path = user_options["mail-dir-path"].as<std::string>();
    mails = MailsFromDirectory(mail_directory_path, bucket_scheme);
  }

  // Read the index
  search_index search_index;
  if (user_options.count("index-file-path")) {
    std::string index_file_path = user_options["index-file-path"].as<std::string>();
    search_index = IndexFromFile(index_file_path);
  }

  std::uint32_t num_of_parties = 0;

  // Do several iterations for more consistent benchmarks
  const std::uint32_t num_of_iterations = 1;
  for (std::uint32_t iteration = 1; iteration <= num_of_iterations; iteration++) {
    // Initialize a party pointer
    encrypto::motion::PartyPointer party{CreateParty(user_options)};

    // Construct and run the actual search circuit for the inputs
    auto search_results = PrivMailSearch(party, search_queries, modifier_chain_share, mails, search_index, bucket_scheme, search_mode);

    // Save the runtime statistics
    const auto& runtime_statistics = party->GetBackend()->GetRunTimeStatistics();
    accumulated_runtime_statistics.Add(runtime_statistics.front());

    // Save the communication statistics
    const auto& communication_statistics = party->GetCommunicationLayer().GetTransportStatistics();
    accumulated_communication_statistics.Add(communication_statistics);

    // Print the result (shares) for each party
    //std::cout << "Search Result (party " << party->GetConfiguration()->GetMyId() << ", iteration " << iteration << "): ";
    //for (auto& search_result : search_results) std::cout << search_result.As<bool>();
    //std::cout << std::endl;

    // Save the number of parties for stats
    num_of_parties = party->GetConfiguration()->GetNumOfParties();
  }

  if (user_options.count("json-path")) {
    // Save the statistics in a JSON file
    auto stats_json = accumulated_runtime_statistics.ToJson();
    for (auto comm_stat : accumulated_communication_statistics.ToJson()) {
      // Add also the communication stats in the json object
      stats_json[comm_stat.key()] = comm_stat.value();
    }

    stats_json["project_name"] = "PrivMail";
    stats_json["protocol"] = "BooleanGMW";  // This is fixed at least for now

    stats_json["search_mode"] = search_mode_string;
    stats_json["num_of_parties"] = num_of_parties;

    stats_json["num_of_emails"] = mails.size();
    stats_json["num_of_emails_in_index"] = search_index.num_of_emails;

    std::uint32_t keyword_characters = 0;
    std::uint32_t keyword_buckets = 0;
    for (auto& query : search_queries) {
      keyword_characters += GetCharacterLengthFromBase64(query.keyword_truncated);
      keyword_buckets += query.bucket_size;
    }
    stats_json["keyword_characters"] = keyword_characters;
    stats_json["keyword_buckets"] = keyword_buckets;

    std::uint32_t email_characters = 0;
    for (auto& mail : mails) {
      email_characters += GetCharacterLengthFromBase64(mail.secret_share_truncated_block);
    }
    stats_json["email_characters"] = email_characters;

    std::ofstream stats_file;
    stats_file.open(user_options["json-path"].as<std::string>());
    stats_file << stats_json;
    stats_file.close();
  } else {
    // Print the statistics
    std::cout << encrypto::motion::PrintStatistics(fmt::format("PrivMail", ""),
                                                   accumulated_runtime_statistics,
                                                   accumulated_communication_statistics);
  }

  return EXIT_SUCCESS;
}

std::vector<search_query> SearchQueriesFromFile(const YAML::Node& search_query_yaml_file) {
  std::vector<search_query> search_queries;
  // Copy data over to queries
  for (const auto& query_from_file : search_query_yaml_file["keywords"]) {
    search_query query;
    // Skip if 'field' is only item in list
    if (query_from_file.size() == 1) {
      continue;
    }
    query.keyword = query_from_file["keyword"].as<std::string>();
    query.bucket_size = query_from_file["keyword_bucket_size"].as<std::uint32_t>();
    query.keyword_bucketed = query_from_file["keyword_bucketed"].as<std::string>();
    query.keyword_length_mask = query_from_file["keyword_length_mask"].as<std::string>();
    query.keyword_truncated = query_from_file["keyword_truncated"].as<std::string>();
    search_queries.push_back(query);
  }
  return search_queries;
}

std::vector<mail_structure> MailsFromDirectory(const std::string& mail_directory_path, const std::vector<std::uint32_t> bucket_scheme) {
  std::uint32_t max_seq_number = 0;

  for (auto& file_path : std::filesystem::directory_iterator(mail_directory_path)) {
    YAML::Node mail_yaml_file = YAML::LoadFile(file_path.path());

    // Update the maximum sequence number
    if (mail_yaml_file["sequence_number"].as<uint32_t>() > max_seq_number) {
      max_seq_number = mail_yaml_file["sequence_number"].as<uint32_t>();
    }
  }

  std::vector<mail_structure> mails(max_seq_number + 1);

  for (auto& file_path : std::filesystem::directory_iterator(mail_directory_path)) {
    YAML::Node mail_yaml_file = YAML::LoadFile(file_path.path());
    std::uint32_t sequence_number = mail_yaml_file["sequence_number"].as<std::uint32_t>();

    // Copy data over to mail
    mail_structure mail;
    mail.subject = mail_yaml_file["subject"].as<std::string>();
    mail.secret_share_block = mail_yaml_file["secret_share_block"].as<std::string>();
    mail.secret_share_truncated_block = mail_yaml_file["secret_share_truncated_block"].as<std::string>();

    for (auto& bucket_size : bucket_scheme) {
      if (mail_yaml_file["secret_share_bucket_blocks"][bucket_size]) {
        bucket_block bucket;
        bucket.bucket_size = bucket_size;
        bucket.words = mail_yaml_file["secret_share_bucket_blocks"][bucket_size].as<std::vector<std::string>>();
        mail.buckets.push_back(bucket);
      }
    }
    mails[sequence_number] = mail;
  }
  return mails;
}

search_index IndexFromFile(const std::string& index_file_path) {
  search_index search_index;
  YAML::Node index_yaml_file = YAML::LoadFile(index_file_path);

  search_index.num_of_emails = index_yaml_file["num_of_emails"].as<uint32_t>();
  for (const auto& bucket : index_yaml_file["INDEX_BUCKETS"]) {
    index_bucket index;
    index.bucket_size = bucket.first.as<std::uint32_t>();
    for (const auto& bucket_item_dict : bucket.second) {
      for (auto& bucket_item : bucket_item_dict) {
        std::string word = bucket_item.first.as<std::string>();
        std::string occurrence_string = bucket_item.second.as<std::string>();
        index.word_and_occurrence_strings.push_back(std::make_pair(word, occurrence_string));
      }
    }
    search_index.index_buckets.push_back(index);
  }
  return search_index;
}

const std::regex kPartyArgumentRegex(
    "(\\d+),(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}),(\\d{1,5})");

bool CheckPartyArgumentSyntax(const std::string& party_argument) {
  // other party's id, IP address, and port
  return std::regex_match(party_argument, kPartyArgumentRegex);
}

std::tuple<std::size_t, std::string, std::uint16_t> ParsePartyArgument(
    const std::string& party_argument) {
  std::smatch match;
  std::regex_match(party_argument, match, kPartyArgumentRegex);
  auto id = boost::lexical_cast<std::size_t>(match[1]);
  auto host = match[2];
  auto port = boost::lexical_cast<std::uint16_t>(match[3]);
  return {id, host, port};
}

// <variables map, help flag>
std::pair<program_options::variables_map, bool> ParseProgramOptions(int ac, char* av[]) {
  using namespace std::string_view_literals;
  constexpr std::string_view kConfigFileMessage =
      "configuration file, other arguments will overwrite the parameters read from the configuration file"sv;
  bool print, help;
  boost::program_options::options_description description("Allowed options");
  // clang-format off
  description.add_options()
      ("help,h", program_options::bool_switch(&help)->default_value(false),"produce help message")
      ("disable-logging,l","disable logging to file")
      ("print-configuration,p", program_options::bool_switch(&print)->default_value(false), "print configuration")
      ("configuration-file,f", program_options::value<std::string>(), kConfigFileMessage.data())
      ("my-id", program_options::value<std::size_t>(), "my party id")
      ("parties", program_options::value<std::vector<std::string>>()->multitoken(), "info (id,IP,port) for each party e.g., --parties 0,127.0.0.1,23000 1,127.0.0.1,23001")
      ("search-mode", program_options::value<std::string>()->default_value("normal"), "choose from search mode options: [normal|hidden|bucket|index]")
      ("query-file-path", program_options::value<std::string>(),
            "get party's path for query file, include path e.g. ../../../privmail-incoming-proxy/secret_shared_query_share1/query_test_file_1.yaml")
      ("mail-dir-path", program_options::value<std::string>(),
            "get party's mail directory path, include path e.g. ../../../privmail-smtp-server/mail_data")
      ("index-file-path", program_options::value<std::string>(),
            "get party's path for index file, include path e.g. ../../../privmail-incoming-proxy/index-files/index_file_1.yaml")
      ("json-path", program_options::value<std::string>(),
            "define path to the benchmarks json file");
  // clang-format on

  program_options::variables_map user_options;

  program_options::store(program_options::parse_command_line(ac, av, description), user_options);
  program_options::notify(user_options);

  // argument help or no arguments (at least a configuration file is expected)
  if (user_options["help"].as<bool>() || ac == 1) {
    std::cout << description << "\n";
    return std::make_pair<program_options::variables_map, bool>({}, true);
  }

  // read configuration file
  if (user_options.count("configuration-file")) {
    std::ifstream ifs(user_options["configuration-file"].as<std::string>().c_str());
    program_options::variables_map user_option_config_file;
    program_options::store(program_options::parse_config_file(ifs, description), user_options);
    program_options::notify(user_options);
  }

  // print parsed parameters
  if (user_options.count("my-id")) {
    if (print) std::cout << "My id " << user_options["my-id"].as<std::size_t>() << std::endl;
  } else
    throw std::runtime_error("My id is not set but required");

  if (user_options.count("parties")) {
    const std::vector<std::string> other_parties{
        user_options["parties"].as<std::vector<std::string>>()};
    std::string parties("Other parties: ");
    for (auto& p : other_parties) {
      if (CheckPartyArgumentSyntax(p)) {
        if (print) parties.append(" " + p);
      } else {
        throw std::runtime_error("Incorrect party argument syntax " + p);
      }
    }
    if (print) std::cout << parties << std::endl;
  } else
    throw std::runtime_error("Other parties' information is not set but required");

  if (!user_options.count("query-file-path")) {
    throw std::runtime_error("Query file path is not set but required");
  }
  // At least one file path is required to be set
  if (!user_options.count("mail-dir-path") && !user_options.count("index-file-path")) {
    throw std::runtime_error("Expected to get either index file path or path to the mail directory");
  }

  return std::make_pair(user_options, help);
}

encrypto::motion::PartyPointer CreateParty(const program_options::variables_map& user_options) {
  const auto parties_string{user_options["parties"].as<const std::vector<std::string>>()};
  const auto number_of_parties{parties_string.size()};
  const auto my_id{user_options["my-id"].as<std::size_t>()};
  if (my_id >= number_of_parties) {
    throw std::runtime_error(fmt::format(
        "My id needs to be in the range [0, #parties - 1], current my id is {} and #parties is {}",
        my_id, number_of_parties));
  }

  encrypto::motion::communication::TcpPartiesConfiguration parties_configuration(number_of_parties);

  for (const auto& party_string : parties_string) {
    const auto [party_id, host, port] = ParsePartyArgument(party_string);
    if (party_id >= number_of_parties) {
      throw std::runtime_error(
          fmt::format("Party's id needs to be in the range [0, #parties - 1], current id "
                      "is {} and #parties is {}",
                      party_id, number_of_parties));
    }
    parties_configuration.at(party_id) = std::make_pair(host, port);
  }
  encrypto::motion::communication::TcpSetupHelper helper(my_id, parties_configuration);
  auto communication_layer = std::make_unique<encrypto::motion::communication::CommunicationLayer>(
      my_id, helper.SetupConnections());
  auto party = std::make_unique<encrypto::motion::Party>(std::move(communication_layer));
  auto configuration = party->GetConfiguration();
  // disable logging if the corresponding flag was set
  const auto logging{!user_options.count("disable-logging")};
  configuration->SetLoggingEnabled(logging);
  configuration->SetOnlineAfterSetup(true);
  return party;
}

search_mode_enum GetSearchMode(std::string const& in_string) {
  if (in_string == "normal") return eNormal;
  if (in_string == "hidden") return eHidden;
  if (in_string == "bucket") return eBucket;
  if (in_string == "index") return eIndex;
  return eError;
}

std::uint32_t GetCharacterLengthFromBase64(const std::string& base64_string) {
  std::size_t num_of_padding_chars = std::count(base64_string.begin(), base64_string.end(), '=');
  return 3 * (base64_string.length() / 4) - num_of_padding_chars;
}
