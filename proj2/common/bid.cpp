#include "bid.h"
#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/sharing/sharing.h"

int32_t test_bid_circuit(e_role role, const std::string& address, uint16_t port, seclvl seclvl,
		uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg, e_sharing sharing){



	if(role == SERVER)
	{
		uint32_t client_input, server_input, max_input, output, times;
		share *s_client_input, *s_server_input, *s_out;

		std::cout << "hello server\nInput: ";
		std::cin >> server_input;
		max_input = server_input;
		times = 5;

		for(uint32_t i = 0; i < times; i++)
		{
			ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);			
			std::vector<Sharing*>& sharings = party->GetSharings();
			Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
			
			s_server_input = circ->PutINGate(max_input, bitlen, SERVER);
			s_client_input = circ->PutDummyINGate(bitlen);

			s_out = BuildBidCircuit(s_client_input, s_server_input, (BooleanCircuit*) circ);
			s_out = circ->PutOUTGate(s_out, ALL);

			party->ExecCircuit();

			output = s_out->get_clear_value<uint32_t>();
			max_input = output;
			std::cout << i+1 << ": " << max_input << std::endl;

			delete party;
		}
		std::cout << "final: " << output << std::endl;
	}


	else  //role == CLIENT
	{
		uint32_t client_input, server_input, output;
		share *s_client_input, *s_server_input, *s_out;
		std::cout << "hello client, Guess number: ";
		std::cin >> client_input;

		ABYParty* party = new ABYParty(role, address, port, seclvl, bitlen, nthreads, mt_alg);
		std::vector<Sharing*>& sharings = party->GetSharings();
		Circuit* circ = sharings[sharing]->GetCircuitBuildRoutine();
		

		s_client_input = circ->PutINGate(client_input, bitlen, CLIENT);
		s_server_input = circ->PutDummyINGate(bitlen);


		s_out = BuildBidCircuit(s_client_input, s_server_input, (BooleanCircuit*) circ);
		s_out = circ->PutOUTGate(s_out, ALL);
		party->ExecCircuit();


		// output = s_out->get_clear_value<uint32_t>();

		delete party;
	
		return 0;
	}

	return 0;
}

share* BuildBidCircuit(share *s_client, share *s_server, BooleanCircuit *bc) {

	share *selec, *out;
	
	selec = bc->PutGTGate(s_client, s_server);
	out = bc->PutMUXGate(s_client, s_server, selec);

	return out;
}
