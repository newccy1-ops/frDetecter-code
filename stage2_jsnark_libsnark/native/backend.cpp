// Phase-separated jsnark -> libsnark interface. KeyGen uses a PUBLIC dummy
// assignment only; Prove owns the actual witness; Verify reads VK/public/proof
// only. The proof implementation is upstream libsnark, never a helper verdict.
#include "CircuitReader.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <fstream>
#include <cctype>
#include <stdexcept>
#include <string>

using PP = libsnark::default_r1cs_gg_ppzksnark_pp;
using Fr = libff::Fr<PP>;
using CS = libsnark::r1cs_constraint_system<Fr>;
using Primary = libsnark::r1cs_primary_input<Fr>;
using Auxiliary = libsnark::r1cs_auxiliary_input<Fr>;
using PK = libsnark::r1cs_gg_ppzksnark_proving_key<PP>;
using VK = libsnark::r1cs_gg_ppzksnark_verification_key<PP>;
using Proof = libsnark::r1cs_gg_ppzksnark_proof<PP>;

template<class T> void save(const std::string& path, const T& object) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create " + path);
    out << object;
    out.flush();
    if (!out) throw std::runtime_error("Cannot serialize " + path);
}
template<class T> T load(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Missing file " + path);
    T object;
    in >> object;
    if (!in) throw std::runtime_error("Invalid serialization " + path);
    return object;
}

// The old upstream compressed-point reader assumes valid points before sqrt.
// Use explicit coordinates and validate all UNTRUSTED proof tokens before
// invoking upstream deserialization. Trusted PK/VK are separately hash-pinned.
Proof load_proof(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("Invalid serialization: missing proof");
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size <= 0 || size > 4096) throw std::runtime_error("Invalid serialization: proof size");
    in.seekg(0, std::ios::beg);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (text.empty() || text.size() > 4096) throw std::runtime_error("Invalid serialization: proof size");
    for (unsigned char c : text)
        if (!std::isdigit(c) && !std::isspace(c)) throw std::runtime_error("Invalid serialization: proof characters");
    std::istringstream fields(text);
    std::vector<std::string> tokens;
    std::string token;
    const auto modulus = libff::alt_bn128_Fq::field_char();
    while (fields >> token) {
        if (token.size() > 77) throw std::runtime_error("Invalid serialization: field size");
        libff::bigint<Fr::num_limbs> value(token.c_str());
        if (mpn_cmp(value.data, modulus.data, Fr::num_limbs) >= 0)
            throw std::runtime_error("Invalid serialization: noncanonical coordinate");
        tokens.push_back(token);
    }
    if (tokens.size() != 11) throw std::runtime_error("Invalid serialization: proof arity");
    for (auto i : {0, 3, 8})
        if (tokens[i] != "0" && tokens[i] != "1") throw std::runtime_error("Invalid serialization: point flag");
    std::istringstream decoded(text);
    Proof proof;
    decoded >> proof;
    if (!decoded) throw std::runtime_error("Invalid serialization: proof parse");
    return proof;
}

struct Circuit { CS cs; Primary primary; Auxiliary auxiliary; };
Circuit parse(char* arith, char* inputs, bool actual_witness) {
    gadgetlib2::GadgetLibAdapter::resetVariableIndex();
    auto pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    CircuitReader reader(arith, inputs, pb);
    Circuit circuit;
    circuit.cs = libsnark::get_constraint_system_from_gadgetlib2(*pb);
    const auto assignment = libsnark::get_variable_assignment_from_gadgetlib2(*pb);
    circuit.cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
    circuit.cs.auxiliary_input_size = assignment.size() - circuit.cs.primary_input_size;
    if (circuit.cs.primary_input_size != 5) throw std::runtime_error("Expected ONE + four public signals");
    if (actual_witness) {
        circuit.primary.assign(assignment.begin(), assignment.begin() + circuit.cs.num_inputs());
        circuit.auxiliary.assign(assignment.begin() + circuit.cs.num_inputs(), assignment.end());
    }
    std::cout << "CONSTRAINTS=" << circuit.cs.num_constraints()
              << " VARIABLES=" << circuit.cs.num_variables() << " PUBLIC=5\n";
    return circuit;
}

Primary read_public(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Missing server public inputs");
    Primary result;
    std::string value;
    const libff::bigint<Fr::num_limbs> modulus = Fr::field_char();
    while (in >> value) {
        if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos || value.size() > 77)
            throw std::runtime_error("Invalid public field encoding");
        const libff::bigint<Fr::num_limbs> integer(value.c_str());
        if (mpn_cmp(integer.data, modulus.data, Fr::num_limbs) >= 0)
            throw std::runtime_error("Noncanonical public input");
        result.emplace_back(integer);
    }
    if (result.size() != 5 || result[0] != Fr::one()) throw std::runtime_error("Public-input arity/ONE mismatch");
    return result;
}

int main(int argc, char** argv) {
    try {
        PP::init_public_params();
        gadgetlib2::initPublicParamsFromDefaultPp();
        if (argc < 2) throw std::runtime_error("keygen | prove | verify | check");
        const std::string action(argv[1]);
        if (action == "keygen" && argc == 7) {
            // inputs is server-created '0 1' only. No client batch/witness is read.
            auto circuit = parse(argv[2], argv[3], false);
            auto keys = libsnark::r1cs_gg_ppzksnark_generator<PP>(circuit.cs);
            save(argv[4], keys.pk);
            save(argv[5], keys.vk);
            save(argv[6], circuit.cs);
            std::cout << "KEYGEN_OK private_batch_read=false\n";
        } else if (action == "prove" && argc == 7) {
            auto circuit = parse(argv[2], argv[3], true);
            if (!circuit.cs.is_satisfied(circuit.primary, circuit.auxiliary))
                throw std::runtime_error("UNSATISFIED_TRAINING_CONSTRAINTS");
            auto pk = load<PK>(argv[4]);
            if (!(pk.constraint_system == circuit.cs)) throw std::runtime_error("Proving-key circuit mismatch");
            const auto expected = read_public(argv[6]);
            if (expected != circuit.primary) throw std::runtime_error("Witness public inputs differ from server expectation");
            const auto proof = libsnark::r1cs_gg_ppzksnark_prover<PP>(pk, circuit.primary, circuit.auxiliary);
            save(argv[5], proof);
            std::cout << "PROVE_OK upstream=libsnark/r1cs_gg_ppzksnark\n";
        } else if (action == "verify" && argc == 5) {
            const auto vk = load<VK>(argv[2]);
            const auto primary = read_public(argv[3]);
            const auto proof = load_proof(argv[4]);
            const bool ok = libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<PP>(vk, primary, proof);
            std::cout << (ok ? "VERIFY_ACCEPTED\n" : "VERIFY_REJECTED\n");
            return ok ? 0 : 2;
        } else if (action == "check" && argc == 4) {
            auto circuit = parse(argv[2], argv[3], true);
            if (!circuit.cs.is_satisfied(circuit.primary, circuit.auxiliary))
                throw std::runtime_error("UNSATISFIED_TRAINING_CONSTRAINTS");
            std::cout << "CONSTRAINT_CHECK_OK\n";
        } else throw std::runtime_error("Invalid phase arguments");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BACKEND_REJECTED: " << error.what() << '\n';
        return 1;
    }
}
