/* Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------*/

#include <ctype.h>
#include <string.h>

#include <log4cxx/logger.h>
#include <log4cxx/basicconfigurator.h>
#include <log4cxx/level.h>

//#include "sawtooth_sdk/sawtooth_sdk.h"
//#include "sawtooth_sdk/exceptions.h"

#include <sawtooth_sdk/sawtooth_sdk.h>
#include <sawtooth_sdk/exceptions.h>

#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>
#include <sstream>

#include <utility>
#include <list>
#include <vector>

#include "address_mapper.h"
#include "json.hpp"

using namespace log4cxx;

using json = nlohmann::json;

static log4cxx::LoggerPtr logger(log4cxx::Logger::getLogger
    ("capbac"));

static const std::string CAPBAC_FAMILY = "capbac";

#define DEFAULT_VALIDATOR_URL "tcp://validator:4004"

// utility function to provide copy conversion from vector of bytes
// to an stl string container.
std::string ToString(const std::vector<std::uint8_t>& in) {
    const char* data = reinterpret_cast<const char*>(&(in[0]));
    std::string out(data, data+in.size());
    return out;
}

// utility function to provide copy conversion from stl string container
// to a vector of bytes.
std::vector<std::uint8_t> ToVector(const std::string& in) {
    std::vector<std::uint8_t> out(in.begin(), in.end());
    return out;
}

/*******************************************************************************
 * CapBACApplicator
 *
 * Handles the processing of CapBAC transactions
 * This is the place where you implement your TF logic
 ******************************************************************************/
class CapBACApplicator:  public sawtooth::TransactionApplicator {

    AddressMapperUPtr address_mapper;

    // implementation of make_unique for C++11 compilers
    template<typename T, typename... Args>
    std::unique_ptr<T> make_unique(Args&&... args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

 public:
    CapBACApplicator(sawtooth::TransactionUPtr txn,
        sawtooth::GlobalStateUPtr state) :
        TransactionApplicator(std::move(txn), std::move(state)){
        this->address_mapper = this->make_unique<AddressMapper>(CAPBAC_FAMILY);
    }

    void CborToParamsAndCheck(
                    std::string& action,
                    json& cap,
                    std::string& identifier,
                    std::string& device,
                    json& req){
        const std::string& raw_data = this->txn->payload();
        std::vector<uint8_t> data_vector = ToVector(raw_data);
        json capbac_cmd = json::from_cbor(data_vector);

        if (!capbac_cmd.is_object()) {
            throw sawtooth::InvalidTransaction(
                ": required CBOR Object as the encoded command");
        }

        auto action_it = capbac_cmd.find("AC");
        if (action_it == capbac_cmd.end()) {
            throw sawtooth::InvalidTransaction(
                ": Action is required");
        }

        action = *action_it;

        auto cap_it = capbac_cmd.find("CT");
        if (cap_it == capbac_cmd.end()) {
            throw sawtooth::InvalidTransaction(
                ": Capability is required");
        }
        cap = *cap_it;

        // capability core check TODO: better
        std::string issuer;
        std::string subject;
        std::string issueIstant;
        std::string signature;

        auto id_it = cap.find("ID");
        if ( id_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'ID' missing (token identifier)");
        } else identifier = *id_it;
        auto ii_it = cap.find("II");
        if ( ii_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'II' missing (issue istant)");
        } else issueIstant = *ii_it;
        auto is_it = cap.find("IS");
        if ( is_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'IS' missing (uri of issuer)");
        } else issuer = *is_it;
        auto su_it = cap.find("SU");
        if ( su_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'SU' missing (public key of the subject)");
        } else subject = *su_it;
        auto de_it = cap.find("DE");
        if ( de_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'DE' missing (uri of device)");
        } else device = *de_it;
        auto si_it = cap.find("SI");
        if ( si_it == cap.end() ) {
            throw sawtooth::InvalidTransaction(
                ": Invalid Capability: 'SI' missing (issuer signature)");
        } else signature = *si_it;

        // Extract user's wallet public key from TransactionHeader
        std::string sender;
        sender = this->txn->header()->GetValue(
            sawtooth::TransactionHeaderSignerPublicKey);

        /*if(!VERIFY(signature,sender)){ TODO
            std::stringstream error;
            error << " Invalid signature: Token Issuer: " << issuer
            << " Transaction signer: " << sender;
            throw sawtooth::InvalidTransaction( error.str());
        }*/

        //case 1: issuer == device

        /* notting to check */

        //case 2: delegation

        if(issuer != device){
            if ( cap.find("PA") == cap.end() ) {
                throw sawtooth::InvalidTransaction(
                    ": Invalid Capability: 'PA' required (ID of the parent token)");
            }
        }

    }

    void Apply() {

        LOG4CXX_DEBUG(logger, "CapBACApplicator::Apply");

        std::string action;
        std::string identifier;
        std::string device;
        json cap;
        json req;

        // Extract action, capability and request from encoded paylod (+ check)
        this->CborToParamsAndCheck(action, cap, identifier, device, req);

        // Choose what to do based on action
        if (action == "issue") {
            this->IssueToken(cap,identifier,device);
        }
        else {
            std::stringstream error;
            error << " Invalid action: '" << action << "'";
            throw sawtooth::InvalidTransaction(error.str());
        }
    }

    // Make a 70-character(35-byte) address to store and retrieve the state
    std::string MakeAddress(const std::string& name) {
        return this->address_mapper->MakeAddress(name, 64, std::string::npos);
    }

    // Handle the CapBAC issue action
    void IssueToken(const json& cap, const std::string& identifier,const std::string& device) {

        // Retrieve unique address for the device's tokens
        auto address = this->MakeAddress(device);

        LOG4CXX_DEBUG(logger, "CapBACApplicator::IssueToken"
            << " ID: " << identifier
            << " Device: " << device
            << " Address: " << address
            );

        // Value is range checked earlier during cbor deserialization
        std::string state_value_rep;
        json state_value_map;
        if(this->state->GetState(&state_value_rep, address)) {
            if (state_value_rep.length() != 0) { // empty rep
                std::vector<std::uint8_t> state_value_rep_v = ToVector(state_value_rep);
                state_value_map = json::from_cbor(state_value_rep_v);
                if (state_value_map.find(identifier) != state_value_map.end()) {
                    std::stringstream error;
                    error << " Token " << identifier << " already issued";
                    throw sawtooth::InvalidTransaction(error.str());
                }
            }
        }

        //check delegation
        auto current = cap;
        if (*current.find("IS") != *current.find("DE")){
            auto parent_it = state_value_map.find(*current.find("PA"));
            if ( parent_it == state_value_map.end()){
                std::stringstream error;
                error << " Parent token" << *current.find("PA") << " revoked";
                throw sawtooth::InvalidTransaction(error.str());
            }
            if ( *(*parent_it).find("SU") != this->txn->header()->GetValue(
                sawtooth::TransactionHeaderSignerPublicKey)){
                std::stringstream error;
                error << " Parent token" << *current.find("PA") << " subject not matching";
                throw sawtooth::InvalidTransaction(error.str());
            }
        }

        // save the whole capabilty on the state at the corresponding address
        state_value_map[identifier] = cap;

        // encode the value map back to cbor for storage.
        std::vector<std::uint8_t> state_value_rep_vec = json::to_cbor(state_value_map);
        state_value_rep = ToString(state_value_rep_vec);
        this->state->SetState(address, state_value_rep);
    }
};

/*******************************************************************************
 * CapBACHandler
 *
 * This class will be registered as the transaction processor handler
 * with validator
 * It sets the namespaceprefix, versions, TF and types of transactions
 * that can be handled by this TP - via the apply method
 ******************************************************************************/
class CapBACHandler: public sawtooth::TransactionHandler {
 public:
    // Generating a namespace prefix in the default constructor
    CapBACHandler() {
        AddressMapperUPtr addr(new AddressMapper(CAPBAC_FAMILY));

        namespacePrefix = addr->GetNamespacePrefix();
    }

    std::string transaction_family_name() const {
        return std::string(CAPBAC_FAMILY);
    }

    std::list<std::string> versions() const {
        return { "1.0" };
    }

    std::list<std::string> namespaces() const {
        return { namespacePrefix };
    }

    sawtooth::TransactionApplicatorUPtr GetApplicator(
            sawtooth::TransactionUPtr txn,
            sawtooth::GlobalStateUPtr state) {
        return sawtooth::TransactionApplicatorUPtr(
            new CapBACApplicator(std::move(txn), std::move(state)));
    }

 private:
    std::string namespacePrefix;
};

int main(int argc, char** argv) {
    try {
        const std::string connectToValidatorUrl = DEFAULT_VALIDATOR_URL;

        // Set up a simple configuration that logs on the console.
        BasicConfigurator::configure();

        // Set logging verbosity to max
        logger->setLevel(Level::getAll());

        // Create a transaction processor

        // 1. connect to validator at connectToValidatorUrl
        sawtooth::TransactionProcessorUPtr processor(
            sawtooth::TransactionProcessor::Create(connectToValidatorUrl));

        // 2. create a transaction handler for the CapBAC TF
        sawtooth::TransactionHandlerUPtr transaction_handler(
            new CapBACHandler());

        // 3. register the transaction handler with validator
        processor->RegisterHandler(
            std::move(transaction_handler));

        // 4. run the transaction processor
        processor->Run();

        return 0;
    } catch(std::exception& e) {
        std::cerr << "Unexpected exception exiting: " << std::endl;
        std::cerr << e.what() << std::endl;
    } catch(...) {
        std::cerr << "Exiting due to unknown exception." << std::endl;
    }

    return -1;

}