// (c) 2022-present Pttn (https://riecoin.xyz/StellaPool-Mini)

#include "Pool.hpp"

void StratumJob::coinbase1Gen() {
	// Version (01000000)
	coinbase1 = {0x01, 0x00, 0x00, 0x00};
	// Input Count (01)
	coinbase1.push_back(1);
	// Input TXID (0000000000000000000000000000000000000000000000000000000000000000)
	for (uint32_t i(0) ; i < 32 ; i++) coinbase1.push_back(0x00);
	// Input VOUT (FFFFFFFF)
	for (uint32_t i(0) ; i < 4 ; i++) coinbase1.push_back(0xFF);
	// ScriptSig Size (Pool Signature Length + Block Height Push Size (1-4 added later) + ExtraNonces Lengths)
	coinbase1.push_back(poolSignature.size() + extraNonce1Length + extraNonce2Length);
	// Block Height (Bip 34)
	if (height < 17) {
		coinbase1.back()++;
		coinbase1.push_back(80 + height);
	}
	else if (height < 128) {
		coinbase1.back() += 2;
		coinbase1.push_back(1);
		coinbase1.push_back(height);
	}
	else if (height < 32768) {
		coinbase1.back() += 3;
		coinbase1.push_back(2);
		coinbase1.push_back(height % 256);
		coinbase1.push_back((height/256) % 256);
	}
	else {
		coinbase1.back() += 4;
		coinbase1.push_back(3);
		coinbase1.push_back(height % 256);
		coinbase1.push_back((height/256) % 256);
		coinbase1.push_back((height/65536) % 256);
	}
}
void StratumJob::coinbase2Gen(const std::vector<uint8_t>& scriptPubKey) {
	const std::vector<uint8_t> dwc(hexStrToV8(default_witness_commitment)); // for SegWit
	// Remaining part of ScriptSig (the Pool Signature; the Block height is in Coinbase1 and the Extra Nonces are not included in Coinbase2)
	coinbase2 = std::vector<uint8_t>(poolSignature.begin(), poolSignature.end());
	// Input Sequence (FFFFFFFF)
	for (uint32_t i(0) ; i < 4 ; i++) coinbase2.push_back(0xFF);
	// Output Count
	coinbase2.push_back(1);
	uint64_t reward(coinbasevalue);
	if (dwc.size() > 0) coinbase2.back()++; // Dummy Output for SegWit
	// Output Value
	for (uint32_t i(0) ; i < 8 ; i++) {
		coinbase2.push_back(reward % 256);
		reward /= 256;
	}
	// Output/ScriptPubKey Length
	coinbase2.push_back(scriptPubKey.size());
	// ScriptPubKey (for the Pool payout address)
	coinbase2.insert(coinbase2.end(), scriptPubKey.begin(), scriptPubKey.end());
	// Dummy output for SegWit
	if (dwc.size() > 0) {
		// No reward
		for (uint32_t i(0) ; i < 8 ; i++) coinbase2.push_back(0);
		// Output Length
		coinbase2.push_back(dwc.size());
		// default_witness_commitment from GetBlockTemplate
		coinbase2.insert(coinbase2.end(), dwc.begin(), dwc.end());
	}
	// Lock Time (00000000)
	for (uint32_t i(0) ; i < 4 ; i++) coinbase2.push_back(0);
}
std::vector<uint8_t> StratumJob::coinBaseGen(const std::string &extraNonce1Str, const std::string &extraNonce2Str) {
	std::vector<uint8_t> coinbase;
	const std::vector<uint8_t> dwc(hexStrToV8(default_witness_commitment)); // for SegWit
	coinbase = coinbase1;
	// Marker (00) and Flag (01) for SegWit
	if (dwc.size() > 0)
		coinbase.insert(coinbase.begin() + 4, {0x00, 0x01});
	// Extra Nonces
	std::vector<uint8_t> extraNonce1(hexStrToV8(extraNonce1Str)), extraNonce2(hexStrToV8(extraNonce2Str));
	coinbase.insert(coinbase.end(), extraNonce1.begin(), extraNonce1.end());
	coinbase.insert(coinbase.end(), extraNonce2.begin(), extraNonce2.end());
	// Coinbase 2
	coinbase.insert(coinbase.end(), coinbase2.begin(), coinbase2.end());
	// Witness of the Coinbase Input for SegWit
	if (dwc.size() > 0) {
		// Number of Witnesses/stack items
		coinbase.insert(coinbase.end() - 4, 1);
		// Witness Length
		coinbase.insert(coinbase.end() - 4, 32);
		// Witness of the Coinbase Input
		for (uint32_t i(0) ; i < 32 ; i++) coinbase.insert(coinbase.end() - 4, 0x00);
	}
	return coinbase;
}
std::array<uint8_t, 32> StratumJob::coinbaseTxId(const std::string &extraNonce1Str, const std::string &extraNonce2Str) const {
	std::vector<uint8_t> coinbase, extraNonce1(hexStrToV8(extraNonce1Str)), extraNonce2(hexStrToV8(extraNonce2Str));
	coinbase.insert(coinbase.end(), coinbase1.begin(), coinbase1.end());
	coinbase.insert(coinbase.end(), extraNonce1.begin(), extraNonce1.end());
	coinbase.insert(coinbase.end(), extraNonce2.begin(), extraNonce2.end());
	coinbase.insert(coinbase.end(), coinbase2.begin(), coinbase2.end());
	return sha256d(coinbase.data(), coinbase.size());
}
void StratumJob::merkleRootGen(const std::string &extraNonce1Str, const std::string &extraNonce2Str) {
	const std::array<uint8_t, 32> cbHash(coinbaseTxId(extraNonce1Str, extraNonce2Str));
	txHashes.insert(txHashes.begin(), cbHash);
	bh.merkleRoot = calculateMerkleRoot(txHashes);
}

static size_t curlWriteCallback(void *data, size_t size, size_t nmemb, std::string *s) {
	s->append((char*) data, size*nmemb);
	return size*nmemb;
}
nlohmann::json Pool::_sendRequestToWallet(CURL *curl, const std::string &method, const nlohmann::json &params) const {
	static std::atomic<uint64_t> id(0ULL);
	nlohmann::json jsonObj;
	if (curl) {
		std::string s;
		const nlohmann::json request{{"method", method}, {"params", params}, {"id", id++}};
		const std::string requestStr(request.dump());
		std::string credentials(configuration.options().walletUsername + ":" + configuration.options().walletPassword);
		if (configuration.options().walletCookie != "") {
			std::ifstream file(configuration.options().walletCookie, std::ios::in);
			if (!file) {
				std::cerr << "Could not open Cookie '"s << configuration.options().walletCookie << "'!"s << std::endl;
				std::cerr << "Check that the Server is running, that the Cookie does exist at this path, and that this instance of StellaPool can read it."s << std::endl;
				return {};
			}
			std::getline(file, credentials);
		}
		curl_easy_setopt(curl, CURLOPT_URL, ("http://"s + configuration.options().walletHost + ":"s + std::to_string(configuration.options().walletPort) + "/wallet/"s + configuration.options().walletName).c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, requestStr.size());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestStr.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
		curl_easy_setopt(curl, CURLOPT_USERPWD, credentials.c_str());
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30); // Have some margin for transactions using a lot of Inputs, which take a lot of time to be created
		const CURLcode cc(curl_easy_perform(curl));
		if (cc != CURLE_OK)
			ERRORMSG("Curl_easy_perform() failed: " << curl_easy_strerror(cc));
		else {
			try {jsonObj = nlohmann::json::parse(s);}
			catch (nlohmann::json::parse_error &e) {
				if (s.size() == 0)
					std::cout << "Nothing was received from the server!" << std::endl;
				else {
					std::cout << "Received bad JSON object!" << std::endl;
					std::cout << "Server message was: " << s << std::endl;
				}
			}
		}
	}
	return jsonObj;
}

static uint32_t checkConstellation(mpz_class n, const std::vector<uint32_t> offsets, const uint32_t iterations) {
	uint32_t sharePrimeCount(0);
	for (const auto &offset : offsets) {
		n += offset;
		if (mpz_probab_prime_p(n.get_mpz_t(), iterations) != 0)
			sharePrimeCount++;
		else if (sharePrimeCount < 2)
			return 0;
	}
	return sharePrimeCount;
}
uint64_t Pool::_checkPoW(const StratumJob& job, const std::vector<uint8_t>& nOffsetV8) { // See the Riecoin Core's CheckProofOfWork function, or read https://riecoin.xyz/Guides/PoWImplementation/
	if (job.powVersion != 1) {
		ERRORMSG("Unknown PoW Version " << job.powVersion << ", please upgrade StellaPool!");
		return 0U;
	}
	uint64_t nBits64(job.bh.bits);
	const uint8_t* rawOffset(nOffsetV8.data()); // [31-30 Primorial Number|29-14 Primorial Factor|13-2 Primorial Offset|1-0 Difficulty Offset/Version]
	const uint16_t offsetFirst16(reinterpret_cast<const uint16_t*>(&rawOffset[0])[0]);
	if ((offsetFirst16 & 31) != 2)
		return 0U;
	
	if (decodeBits(nBits64, job.powVersion) < 264U) return 0U;
	if ((offsetFirst16 & 65535U) != 2) {
		nBits64 += (offsetFirst16 & 65504U) << 8U;
		if (nBits64 > 4294967295ULL)
			nBits64 = 4294967295ULL;
	}
	const uint32_t difficultyIntegerPart(decodeBits(nBits64, job.powVersion));
	const uint32_t trailingZeros(difficultyIntegerPart - 264U);
	mpz_class offsetLimit(1);
	offsetLimit <<= trailingZeros;
	const uint16_t primorialNumber(reinterpret_cast<const uint16_t*>(&rawOffset[30])[0]);
	mpz_class primorial(1), primorialFactor, primorialOffset;
	for (uint16_t i(0U) ; i < primorialNumber ; i++) {
		primorial *= primeTable[i];
		if (primorial > offsetLimit)
			return 0U;
	}
	mpz_import(primorialFactor.get_mpz_t(), 16, -1, sizeof(uint8_t), 0, 0, &rawOffset[14]);
	mpz_import(primorialOffset.get_mpz_t(), 12, -1, sizeof(uint8_t), 0, 0, &rawOffset[2]);
	const mpz_class target(job.bh.target(job.powVersion, (offsetFirst16 & 65504U) >> 5)),
			offset(primorial - (target % primorial) + primorialFactor*primorial + primorialOffset);
	if (offset >= offsetLimit)
		return 0U;
	const mpz_class result(target + offset);
	uint32_t highestSharePrimeCount(0);
	for (const auto &pattern : job.acceptedPatterns) {
		const uint32_t sharePrimeCount(checkConstellation(result, pattern, 32));
		if (sharePrimeCount > highestSharePrimeCount)
			highestSharePrimeCount = sharePrimeCount;
	}
	return highestSharePrimeCount;
}

static uint32_t toBEnd32(uint32_t n) { // Converts a uint32_t to Big Endian (ABCDEF01 -> 01EFCDAB in a Little Endian system, do nothing in a Big Endian system)
	const uint8_t *tmp((uint8_t*) &n);
	return (uint32_t) tmp[3] | ((uint32_t) tmp[2]) << 8 | ((uint32_t) tmp[1]) << 16 | ((uint32_t) tmp[0]) << 24;
}
static std::vector<std::array<uint8_t, 32>> calculateMerkleBranches(const std::vector<std::array<uint8_t, 32>>& transactions) {
	std::vector<std::array<uint8_t, 32>> merkleBranches, tmp(transactions);
	if (tmp.size() > 0) {
		while (tmp.size() > 0) {
			merkleBranches.push_back(tmp[0]);
			if (tmp.size() % 2 == 0)
				tmp.push_back(tmp.back());
			std::vector<std::array<uint8_t, 32>> tmp2;
			for (uint64_t j(1) ; j + 1 < tmp.size() ; j += 2) {
				std::vector<uint8_t> toHash(64, 0);
				std::copy(tmp[j].begin(), tmp[j].end(), toHash.begin());
				std::copy(tmp[j + 1].begin(), tmp[j + 1].end(), toHash.begin() + 32);
				tmp2.push_back(sha256d(toHash.data(), 64));
			}
			tmp = tmp2;
		}
	}
	return merkleBranches;
}
std::string Pool::_generateMiningNotify(const bool cleanJobs) {
	StratumJob currentJob;
	if (_currentJobs.size() == 0) {
		ERRORMSG("No available job");
		return ""s;
	}
	currentJob = _currentJobs.back();
	std::ostringstream oss;
	oss << "{\"id\": null, \"method\": \"mining.notify\", \"params\": [\"";
	oss << std::hex << currentJob.id << "\"";
	oss << ", \"";
	std::array<uint8_t, 32> previousblockhashBe;
	for (uint8_t i(0) ; i < 8 ; i++) reinterpret_cast<uint32_t*>(previousblockhashBe.data())[i] = toBEnd32(reinterpret_cast<uint32_t*>(currentJob.bh.previousblockhash.data())[i]);
	oss << v8ToHexStr(a8ToV8(previousblockhashBe)) << "\"";
	oss << ", \"" << v8ToHexStr(currentJob.coinbase1) << "\"";
	oss << ", \"" << v8ToHexStr(currentJob.coinbase2) << "\"";
	oss << ", [";
	std::vector<std::array<uint8_t, 32>> merkleBranches(calculateMerkleBranches(currentJob.txHashes));
	for (uint64_t i(0) ; i < merkleBranches.size() ; i++) {
		oss << "\"" << v8ToHexStr(a8ToV8(merkleBranches[i])) << "\"";
		if (i + 1 < merkleBranches.size())
			oss << ", ";
	}
	oss << "]";
	oss << ", \"" << std::setfill('0') << std::setw(8) << std::hex << currentJob.bh.version << "\"";
	oss << ", \"" << std::setfill('0') << std::setw(8) << std::hex << currentJob.bh.bits << "\"";
	oss << ", \"" << std::setfill('0') << std::setw(8) << std::hex << static_cast<uint32_t>(currentJob.bh.curtime) << "\"";
	oss << ", " << (cleanJobs ? "true" : "false");
	oss << ", " << currentJob.powVersion;
	oss << ", [";
	for (uint64_t i(0) ; i < currentJob.acceptedPatterns.size() ; i++) {
		oss << "[" << formatContainer(currentJob.acceptedPatterns[i]) << "]";
		if (i + 1 !=  currentJob.acceptedPatterns.size())
			oss << ", ";
	}
	oss << "]]}\n";
	return oss.str();
}

std::string stratumResponseStr(const std::string &id, const std::string &result) {
	return "{\"id\": "s + id + ", \"result\": "s + result + ", \"error\": null}\n"s;
}
std::string stratumErrorStr(const std::string &id, const int code, const std::string &message) {
	return "{\"id\": "s + id + ", \"result\": null, \"error\": ["s + std::to_string(code) + ", \"" + message + "\"]}\n"s;
}

std::pair<std::string, bool> Pool::_processMessage(const std::pair<std::shared_ptr<Worker>, std::string>& message) {
	const std::shared_ptr<Worker> worker(message.first);
	if (!worker) {
		ERRORMSG("Processing message from a null worker");
		return {stratumErrorStr("null", 20, "Invalid worker"s), true};
	}
	std::string method;
	std::string messageId("null");
	nlohmann::json jsonMessage;
	try {
		jsonMessage = nlohmann::json::parse(message.second);
	}
	catch (std::exception &e) {
		LOGMSG("Received invalid JSON message from " << worker->str());
		return {stratumErrorStr("null", 20, "Invalid JSON message"s), true};
	}
	try {
		uint64_t messageIdUInt(jsonMessage["id"]);
		messageId = std::to_string(messageIdUInt);
	}
	catch (...) {
		messageId = "null";
	}
	try {
		method = jsonMessage["method"];
	}
	catch (std::exception &e) {
		LOGMSG("Received message with missing or invalid method from " << worker->str());
		return {stratumErrorStr(messageId, 20, "Missing or invalid method"s), true};
	}
	if (method == "mining.subscribe") {
		worker->state = Worker::State::SUBSCRIBED;
		LOGMSG("Subscribed " << worker->str());
		return {stratumResponseStr(messageId, "[[[\"mining.notify\", \""s + worker->extraNonce1 + "\"]],\""s + worker->extraNonce1 + "\", "s + std::to_string(extraNonce2Length) + "]"s), false};
	}
	else if (method == "mining.authorize") {
		if (worker->state != Worker::State::SUBSCRIBED) {
			LOGMSG("Not authorizing unsubscribed " << worker->str());
			return {stratumErrorStr(messageId, 25, "Not subscribed"s), true};
		}
		else {
			std::string name;
			try {
				name = jsonMessage["params"][0];
			}
			catch (std::exception &e) {
				LOGMSG("Not authorizing (missing or invalid name) " << worker->str());
				return {stratumErrorStr(messageId, 20, "Missing or invalid name"s), true};
			}
			worker->name = name;
			{
				const std::lock_guard lock(_stateMutex);
				_workerStats[worker->id].name = name;
			}
			worker->state = Worker::State::AUTHORIZED;
			LOGMSG("Authorized " << worker->str() << "; user " << worker->name);
			return {stratumResponseStr(messageId, "true") + _generateMiningNotify(true) + "{\"id\": null, \"method\": \"client.show_message\", \"params\": [\"Hello "s + worker->name + ", Happy Mining!\"]}\n"s, false};
		}
	}
	else if (method == "mining.submit") {
		if (worker->state != Worker::State::AUTHORIZED) {
			LOGMSG("Ignoring share from unauthorized " << worker->str());
			return {stratumErrorStr(messageId, 24, "Unauthorized worker"s), true};
		}
		std::string name, id, extranonce2, nTime, nOffset;
		try {
			name = jsonMessage["params"][0];
			id = jsonMessage["params"][1];
			extranonce2 = jsonMessage["params"][2];
			nTime = jsonMessage["params"][3];
			nOffset = jsonMessage["params"][4];
		}
		catch (std::exception &e) {
			LOGMSG("Received invalid submission (invalid parameters) from " << worker->str());
			_recordShare(worker, false, "invalid_params");
			return {stratumErrorStr(messageId, 20, "Invalid params"s), true};
		}
		if (name != worker->name) {
			LOGMSG("Received invalid submission (wrong name) from " << worker->str());
			_recordShare(worker, false, "wrong_worker_name");
			return {stratumErrorStr(messageId, 20, "Wrong name"s), true};
		}
		if (!isHexStrOfSize(extranonce2, 2U*extraNonce2Length)) {
			LOGMSG("Received invalid submission (invalid Extra Nonce 2) from " << worker->str());
			_recordShare(worker, false, "invalid_extranonce2");
			return {stratumErrorStr(messageId, 20, "Invalid Extra Nonce 2 (must be "s + std::to_string(2U*extraNonce2Length) + " hex digits"s), true};
		}
		if (!isHexStr(nTime)) {
			LOGMSG("Received invalid submission (invalid nTime) from " << worker->str());
			_recordShare(worker, false, "invalid_ntime");
			return {stratumErrorStr(messageId, 20, "Invalid nTime (must be a hex str)"s), true};
		}
		if (!isHexStrOfSize(nOffset, 64)) {
			LOGMSG("Received invalid submission (invalid nOffset) from " << worker->str());
			_recordShare(worker, false, "invalid_noffset");
			return {stratumErrorStr(messageId, 20, "Invalid nOffset (must be 64 hex digits)"s), true};
		}
		if (_roundOffsets.find(nOffset) != _roundOffsets.end()) {
			LOGMSG("Received invalid submission (duplicate share) from " << worker->str());
			_recordShare(worker, false, "duplicate_share");
			return {stratumErrorStr(messageId, 22, "Duplicate share"s), true};
		}
		uint64_t jobId;
		try {
			jobId = std::stoll(id, nullptr, 16);
		}
		catch (const std::exception &e) { // This should never happen as a Hex Check was previously done
			ERRORMSG("SToLl failed for some reason while decoding the Job Id - " << e.what());
					_recordShare(worker, false, "invalid_job_id");
			ERRORMSG("Submission was " << message.second);
			return {stratumErrorStr(messageId, 20, "Internal error :|"s), true};
		}
		bool jobFound(false);
		StratumJob shareJob;
		for (const auto &job : _currentJobs) {
			if (job.id == jobId) {
				jobFound = true;
				shareJob = job;
				break;
			}
		}
		if (!jobFound) {
			// LOGMSG("Received invalid submission (job not found) from " << worker->str());
			_recordShare(worker, false, "job_not_found");
			return {stratumErrorStr(messageId, 21, "Job not found"s), false};
		}
		uint64_t shareTimestamp;
		try {
			shareTimestamp = std::stoll(nTime, nullptr, 16);
		}
		catch (const std::exception &e) { // This should never happen as a Hex Check was previously done
			ERRORMSG("SToLl failed for some reason while decoding the Timestamp - " << e.what());
					_recordShare(worker, false, "invalid_timestamp");
			ERRORMSG("Submission was " << message.second);
			return {stratumErrorStr(messageId, 20, "Internal error :|"s), true};
		}
		if (shareTimestamp < shareJob.bh.curtime) {
			LOGMSG("Received invalid submission (timestamp too early) from " << worker->str());
			_recordShare(worker, false, "timestamp_too_early");
			return {stratumErrorStr(messageId, 20, "Timestamp too early (please check your system clock)"s), true};
		}
		else if (shareTimestamp > nowU64() + 5) {
			LOGMSG("Received invalid submission (timestamp too late) from " << worker->str());
			_recordShare(worker, false, "timestamp_too_late");
			return {stratumErrorStr(messageId, 20, "Timestamp too late (please check your system clock))"s), true};
		}
		const std::vector<uint8_t> nOffsetV8(reverse(hexStrToV8(nOffset)));
		if ((*reinterpret_cast<const uint16_t*>(&nOffsetV8.data()[0]) & 31) != 2) {
			LOGMSG("Received invalid submission (invalid PoW Version) from " << worker->str());
			_recordShare(worker, false, "invalid_pow_version");
			return {stratumErrorStr(messageId, 20, "Invalid PoW Version"s), true};
		}
		shareJob.merkleRootGen(worker->extraNonce1, extranonce2);
		const uint64_t sharePrimeCount(_checkPoW(shareJob, nOffsetV8)), sharePrimeCountMin(std::max(4ULL, shareJob.acceptedPatterns[0].size() - 2ULL));
		if (sharePrimeCount < sharePrimeCountMin) {
			LOGMSG("Received invalid submission (too low Share Prime Count) from " << worker->str());
			_recordShare(worker, false, "low_prime_count", sharePrimeCount, sharePrimeCountMin);
			return {stratumErrorStr(messageId, 23, "Received a "s + std::to_string(sharePrimeCount) + "-share, "s + std::to_string(sharePrimeCountMin) + "-shares or better expected"s), true};
		}
		_roundOffsets.insert(nOffset);
		_recordShare(worker, true, "", sharePrimeCount, sharePrimeCountMin);
		worker->latestShareTp = std::chrono::steady_clock::now();
		if (sharePrimeCount > sharePrimeCountMin)
			LOGMSG("Accepted " << sharePrimeCount << "-share from " << worker->str() << " (" << worker->name << ")");
		if (sharePrimeCount >= shareJob.acceptedPatterns[0].size()) {
			LOGMSG("Submitting block with " << shareJob.txHashes.size() << " transaction(s) (including coinbase)...");
			shareJob.transactionsHex = v8ToHexStr(shareJob.coinBaseGen(worker->extraNonce1, extranonce2)) + shareJob.transactionsHex;
			BlockHeader bh(shareJob.bh);
			bh.nOffset = v8ToA8(nOffsetV8);
			std::ostringstream oss;
			oss << v8ToHexStr(bh.toV8());
			// Using the Variable Length Integer format; having more than 65535 transactions is currently impossible
			if (shareJob.txHashes.size() < 0xFD)
				oss << std::setfill('0') << std::setw(2) << std::hex << shareJob.txHashes.size();
			else
				oss << "fd" << std::setfill('0') << std::setw(2) << std::hex << shareJob.txHashes.size() % 256 << std::setw(2) << shareJob.txHashes.size()/256;
			oss << shareJob.transactionsHex;
			nlohmann::json submitblockResponse, submitblockResponseResult, submitblockResponseError;
			try {
				submitblockResponse = _sendRequestToWallet(_curlMain, "submitblock", {oss.str()});
				submitblockResponseResult = submitblockResponse["result"];
				submitblockResponseError = submitblockResponse["error"];
			}
			catch (std::exception &e) {
				ERRORMSG("Could not submit block: " << e.what() << std::endl);
				return {stratumErrorStr(messageId, 20, "Internal error :|"s), true};
			}
			if (submitblockResponseResult == nullptr && submitblockResponseError == nullptr) {
				std::string blockHash;
				try {
					blockHash = _sendRequestToWallet(_curlMain, "getblockhash", {shareJob.height})["result"];
					{
						const std::lock_guard lock(_stateMutex);
						_rounds.back().heightEnd = shareJob.height;
						_rounds.back().timeEnd = nowU64();
						_rounds.back().blockHash = blockHash;
						_rounds.back().difficulty = decodeBits(shareJob.bh.bits, shareJob.powVersion);
						_rounds.back().reward = shareJob.coinbasevalue;
						_rounds.back().finder = name;
					}
					_startNewRound(shareJob.height + 1);
				}
				catch (std::exception &e) {
					ERRORMSG("Could not start a new round: " << e.what() << std::endl);
					return {stratumErrorStr(messageId, 20, "Internal error :|"s), true};
				}
				LOGMSG("Submission accepted :D ! Blockhash: " << blockHash);
			}
			else {
				LOGMSG("Submission rejected :| ! Received: " << submitblockResponse.dump());
				return {stratumErrorStr(messageId, 20, "Your block was rejected by the Riecoin Network :|, really sorry"s), false};
			}
		}
		return {"{\"id\": "s + messageId + ", \"result\": true, \"error\": null}\n"s, false};
	}
	else {
		LOGMSG("Received invalid request (unsupported method) from " << worker->str());
		return {stratumErrorStr(messageId, 20, "Unsupported method "s + method), true};
	}
}

void Pool::_startNewRound(const uint32_t heightStart) {
	{
		const std::lock_guard lock(_stateMutex);
		_rounds.push_back({.id = static_cast<uint32_t>(_rounds.size()), .heightStart = heightStart, .heightEnd = {}, .timeStart = nowU64(), .timeEnd = {}, .confirmations = 0, .blockHash = {}, .difficulty = {}, .reward = {}, .shares = 0U, .finder = {}});
	}
	_roundOffsets.clear();
}

void Pool::_recordShare(
	const std::shared_ptr<Worker>& worker,
	const bool valid,
	const std::string& rejectReason,
	const std::optional<uint64_t>& primeCount,
	const std::optional<uint64_t>& minimumPrimeCount
) {
	const uint64_t timestamp = nowU64();
	const std::lock_guard lock(_stateMutex);

	_recentShares.push_back(Share{
		timestamp,
		worker->id,
		worker->name,
		valid,
		rejectReason,
		primeCount,
		minimumPrimeCount
	});

	if (_recentShares.size() > maxRecentShareRecords)
		_recentShares.erase(
			_recentShares.begin(),
			_recentShares.begin() + (_recentShares.size() - maxRecentShareRecords)
		);

	WorkerStats& stats = _workerStats[worker->id];
	stats.lastShareAt = timestamp;

	if (valid) {
		++_acceptedShares;
		++stats.acceptedShares;

		if (primeCount && *primeCount > stats.bestSharePrimeCount)
			stats.bestSharePrimeCount = *primeCount;

		if (!_rounds.empty())
			++_rounds.back().shares;
	}
	else {
		++_rejectedShares;
		++stats.rejectedShares;
	}
}

void Pool::_removeWorker(const int fileDescriptor) {
	const auto workerIt = _workers.find(fileDescriptor);
	if (workerIt == _workers.end())
		return;

	const std::shared_ptr<Worker> worker = workerIt->second;
	{
		const std::lock_guard lock(_stateMutex);
		const auto statsIt = _workerStats.find(worker->id);
		if (statsIt != _workerStats.end())
			statsIt->second.disconnectedAt = nowU64();
	}

	_workers.erase(workerIt);
	_workerCount.fetch_sub(1, std::memory_order_relaxed);
}

void Pool::_updateStats() {
	CURL *curlStatsUpdater(curl_easy_init());
	std::chrono::time_point<std::chrono::steady_clock> latestDbUpdateTp(std::chrono::steady_clock::now());

	while (_running) {
		// Take a snapshot before performing wallet RPC requests.
		std::vector<Round> roundsToCheck;
		{
			const std::lock_guard lock(_stateMutex);
			roundsToCheck = _rounds;
		}

		std::vector<std::pair<std::size_t, int>> confirmationUpdates;

		const std::size_t firstRoundToCheck =
			roundsToCheck.size() > 101 ? roundsToCheck.size() - 101 : 0;

		for (std::size_t i(firstRoundToCheck); i + 1 < roundsToCheck.size(); i++) {
			const Round &round = roundsToCheck[i];

			if (round.confirmations < 0)
				continue;

			if (round.confirmations >= 100) {
				confirmationUpdates.emplace_back(i, 100);
				continue;
			}

			if (!round.blockHash.has_value())
				continue;

			try {
				const nlohmann::json block(
					_sendRequestToWallet(
						curlStatsUpdater,
						"getblock",
						{round.blockHash.value()}
					)["result"]
				);

				const int confirmations = block["confirmations"].get<int>();
				confirmationUpdates.emplace_back(i, confirmations);

				if (confirmations < 0)
					LOGMSG("Block found in Round " << round.id << " was orphaned :|");
			}
			catch (const std::exception &e) {
				ERRORMSG("Could not get number of confirmations for Block "
					<< round.blockHash.value()
					<< ", it will be attempted again - " << e.what());
			}
		}

		// Apply RPC results and take the snapshots used for this update.
		std::vector<Round> roundsSnapshot;
		std::vector<Share> recentSharesSnapshot;
		std::map<uint32_t, WorkerStats> workerStatsSnapshot;
		uint64_t acceptedSharesSnapshot = 0;
		uint64_t rejectedSharesSnapshot = 0;

		{
			const std::lock_guard lock(_stateMutex);

			for (const auto &[index, confirmations] : confirmationUpdates) {
				if (index >= _rounds.size())
					continue;

				_rounds[index].confirmations = confirmations;

				if (confirmations < 0)
					_rounds[index].reward = 0ULL;
			}

			std::erase_if(_recentShares, [](const auto &entry) {
				return nowU64() - entry.timestamp >= recentSharesTime;
			});

			roundsSnapshot = _rounds;
			recentSharesSnapshot = _recentShares;
			workerStatsSnapshot = _workerStats;
			acceptedSharesSnapshot = _acceptedShares;
			rejectedSharesSnapshot = _rejectedShares;
		}

		const std::size_t workerCount =
			_workerCount.load(std::memory_order_relaxed);

		nlohmann::json statsJson;
		statsJson["pool"] = {
			{"workerCount", workerCount},
			{"acceptedShares", acceptedSharesSnapshot},
			{"rejectedShares", rejectedSharesSnapshot}
		};

		statsJson["rounds"] = nlohmann::json::array();

		for (const auto &round : roundsSnapshot) {
			statsJson["rounds"].push_back({
				{"id", round.id},
				{"heightStart", round.heightStart},
				{"heightEnd", round.heightEnd ? nlohmann::json(*round.heightEnd) : nlohmann::json(nullptr)},
				{"timeStart", round.timeStart},
				{"timeEnd", round.timeEnd ? nlohmann::json(*round.timeEnd) : nlohmann::json(nullptr)},
				{"confirmations", round.confirmations},
				{"blockHash", round.blockHash ? nlohmann::json(*round.blockHash) : nlohmann::json(nullptr)},
				{"difficulty", round.difficulty ? nlohmann::json(*round.difficulty) : nlohmann::json(nullptr)},
				{"reward", round.reward ? nlohmann::json(*round.reward) : nlohmann::json(nullptr)},
				{"shares", round.shares},
				{"finder", round.finder ? nlohmann::json(*round.finder) : nlohmann::json(nullptr)}
			});
		}

		statsJson["workers"] = nlohmann::json::array();

		for (const auto &[id, worker] : workerStatsSnapshot) {
			statsJson["workers"].push_back({
				{"id", id},
				{"name", worker.name},
				{"ip", worker.ip},
				{"port", worker.port},
				{"connectedAt", worker.connectedAt},
				{"disconnectedAt", worker.disconnectedAt ? nlohmann::json(*worker.disconnectedAt) : nlohmann::json(nullptr)},
				{"lastShareAt", worker.lastShareAt},
				{"acceptedShares", worker.acceptedShares},
				{"rejectedShares", worker.rejectedShares},
				{"bestSharePrimeCount", worker.bestSharePrimeCount}
			});
		}

		statsJson["recentShares"] = nlohmann::json::array();

		for (const auto &share : recentSharesSnapshot) {
			statsJson["recentShares"].push_back({
				{"timestamp", share.timestamp},
				{"workerId", share.workerId},
				{"finder", share.finder},
				{"valid", share.valid},
				{"rejectReason", share.rejectReason},
				{"primeCount", share.primeCount ? nlohmann::json(*share.primeCount) : nlohmann::json(nullptr)},
				{"minimumPrimeCount", share.minimumPrimeCount ? nlohmann::json(*share.minimumPrimeCount) : nlohmann::json(nullptr)}
			});
		}

		std::string roundsJsonStr = statsJson.dump(4);
		std::string roundsHtmlStr;

		roundsHtmlStr = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>"s
			"body {color: rgba(255, 255, 255, 0.8); background-color: rgb(16, 0, 24);}"s
			"a {color: rgba(255, 255, 255, 0.9);}"s
			"table {border-collapse: collapse;}"s
			"th, td {border: 1px solid rgba(255, 255, 255, 0.25); padding: 4px;}"s
			"th {background: rgba(255, 255, 255, 0.125);}"s
			"</style><title>"s + versionString + " Recent Stats</title></head><body>"s
			"<h1>"s + versionString + "</h1>";

		if (!roundsSnapshot.empty()) {
			roundsHtmlStr += "<p>Pool session started on "s
				+ timeStr(roundsSnapshot.front().timeStart)
				+ " ("s
				+ formattedDuration(nowU64() - roundsSnapshot.front().timeStart)
				+ " ago)</p>"s;
		}

		roundsHtmlStr += "<h2>Status</h2>"s;
		roundsHtmlStr += "<p>"s + std::to_string(workerCount) + " worker connection(s)</p>"s;
		roundsHtmlStr += "<p>Last Update: "s + timeNowStr() + "</p>"s;

		roundsHtmlStr += "<h2>Active workers for the last "s
			+ formattedDuration(recentSharesTime) + "</h2>"s;

		std::map<std::string, std::pair<uint32_t, uint32_t>> activeWorkers;
		uint32_t validShares(0U);

		for (const auto &share : recentSharesSnapshot) {
			if (activeWorkers.find(share.finder) == activeWorkers.end())
				activeWorkers[share.finder] = std::make_pair(0U, 0U);

			if (share.valid) {
				activeWorkers[share.finder].first++;
				validShares++;
			}
			else
				activeWorkers[share.finder].second++;
		}

		roundsHtmlStr += "<table><tr><th>Worker</th><th>Shares (invalid)</th><th>%</th></tr>"s;

		for (const auto &activeWorker : activeWorkers) {
			const double percentage = validShares > 0
				? 100. * static_cast<double>(activeWorker.second.first)
					/ static_cast<double>(validShares)
				: 0.;

			roundsHtmlStr += "<tr><td>"s + activeWorker.first
				+ "</td><td>"s
				+ std::to_string(activeWorker.second.first)
				+ " ("s + std::to_string(activeWorker.second.second)
				+ ")</td><td>"s + std::to_string(percentage)
				+ "</td></tr>"s;
		}

		roundsHtmlStr += "</table>"s;
		roundsHtmlStr += "<h2>Last Blocks</h2>"s;
		roundsHtmlStr += "<table><tr><th>Round</th><th>Block</th><th>Time (duration)</th><th>Confirmations</th><th>Difficulty</th><th>Reward</th><th>Shares</th><th>Finder</th></tr>"s;

		if (roundsSnapshot.size() >= 2) {
			const std::size_t firstRoundToDisplay =
				roundsSnapshot.size() > 26 ? roundsSnapshot.size() - 26 : 0;

			for (std::size_t i(roundsSnapshot.size() - 1); i-- > firstRoundToDisplay;) {
				const auto &round = roundsSnapshot[i];

				if (!round.heightEnd || !round.timeEnd || !round.blockHash
					|| !round.difficulty || !round.reward || !round.finder)
					continue;

				roundsHtmlStr += "<tr><td>"s + std::to_string(round.id)
					+ "</td><td><a href=\"https://riecoin.xyz/Explorer/Block/"s
					+ round.blockHash.value() + "\">"
					+ std::to_string(round.heightEnd.value())
					+ "</a></td><td>"s
					+ timeStr(round.timeEnd.value()) + " ("s
					+ formattedDuration(round.timeEnd.value() - round.timeStart)
					+ ")"s + "</td><td>"
					+ (round.confirmations >= 0
						? std::to_string(round.confirmations) + "/100"s
						: "Orphaned"s)
					+ "</td><td>"s + std::to_string(round.difficulty.value())
					+ "</td><td>"s
					+ amountStr(static_cast<double>(round.reward.value()) / 1e8)
					+ " RIC</td><td>"s + std::to_string(round.shares)
					+ "</td><td>"s + round.finder.value()
					+ "</td></tr>"s;
			}
		}

		roundsHtmlStr += "</table><p><a href=\""s
			+ configuration.options().statsJsonFile
			+ "\">All Rounds for this Session in Json</a></p>"s;
		roundsHtmlStr += "</body></html>"s;

		std::ofstream jsonFile(configuration.options().statsJsonFile, std::ios::out),
			htmlFile(configuration.options().statsHtmlFile, std::ios::out);

		if (jsonFile)
			jsonFile << roundsJsonStr << std::flush;
		else
			std::cerr << "Unable to write to file "s
				<< configuration.options().statsJsonFile << std::endl;

		if (htmlFile)
			htmlFile << roundsHtmlStr << std::flush;
		else
			std::cerr << "Unable to write debug output to file "s
				<< configuration.options().statsHtmlFile << std::endl;

		latestDbUpdateTp = std::chrono::steady_clock::now();

		while (timeSince(latestDbUpdateTp) < configuration.options().statsUpdateInterval && _running)
			std::this_thread::sleep_for(std::chrono::duration<double>(0.25));
	}

	curl_easy_cleanup(curlStatsUpdater);
}

void Pool::_fetchJob() {
	nlohmann::json getblocktemplate, getblocktemplateResult;
	try {
		getblocktemplate = _sendRequestToWallet(_curlMain, "getblocktemplate", "[{}]"_json);
		if (getblocktemplate == nullptr)
			return;
		getblocktemplateResult = getblocktemplate["result"];
	}
	catch (std::exception &e) {
		std::cout << "Could not get GetBlockTemplate Data!" << std::endl;
		return;
	}
	StratumJob job;
	job.bh = BlockHeader();
	job.transactionsHex = std::string();
	job.txHashes = std::vector<std::array<uint8_t, 32>>();
	job.default_witness_commitment = std::string();
	try {
		job.bh.version = getblocktemplateResult["version"];
		job.bh.previousblockhash = v8ToA8(reverse(hexStrToV8(getblocktemplateResult["previousblockhash"])));
		job.bh.curtime = getblocktemplateResult["curtime"];
		job.bh.bits = std::stoll(std::string(getblocktemplateResult["bits"]), nullptr, 16);
		job.coinbasevalue = getblocktemplateResult["coinbasevalue"];
		for (const auto &transaction : getblocktemplateResult["transactions"]) {
			const std::vector<uint8_t> txId(reverse(hexStrToV8(transaction["txid"])));
			job.transactionsHex += transaction["data"];
			job.txHashes.push_back(v8ToA8(txId));
		}
		job.default_witness_commitment = getblocktemplateResult["default_witness_commitment"];
		job.height = getblocktemplateResult["height"];
		job.powVersion = getblocktemplateResult["powversion"];
		if (job.powVersion != 1) {
			std::cout << "Unsupported PoW Version " << job.powVersion << ", StellaPool is likely outdated!" << std::endl;
			return;
		}
		job.acceptedPatterns = getblocktemplateResult["patterns"].get<decltype(job.acceptedPatterns)>();
		if (job.acceptedPatterns.size() == 0) {
			std::cout << "Empty or invalid accepted patterns list!" << std::endl;
			return;
		}
	}
	catch (...) {
		std::cout << "Received GetBlockTemplate Data with invalid parameters!" << std::endl;
		std::cout << "Json Object was: " << getblocktemplateResult.dump() << std::endl;
		return;
	}
	
	if (_currentJobs.size() == 0 ? true : (job.height != _currentJobs.back().height || timeSince(_latestJobTp) > jobRefreshInterval)) {
		std::string messageToSend;
		job.id = _currentJobId++;
		job.coinbase1Gen();
		job.coinbase2Gen(_scriptPubKey);
		if (_currentJobs.size() == 0) {
			LOGMSG("Started Pool at Block " << job.height << ", difficulty " << FIXED(3) << decodeBits(job.bh.bits, job.powVersion));
			_currentJobs = {job};
			messageToSend = _generateMiningNotify(true);
		}
		else if (job.height != _currentJobs.back().height) {
			LOGMSG("Block " << job.height << ", difficulty " << FIXED(3) << decodeBits(job.bh.bits, job.powVersion));
			_currentJobs = {job};
			messageToSend = _generateMiningNotify(true);
		}
		else {
			LOGMSG("Refreshing current job and broadcasting. " << job.txHashes.size() + 1U << " transaction(s), " << amountStr(static_cast<double>(job.coinbasevalue)/1e8) << " RIC reward"); // Count Coinbase
			_currentJobs.push_back(job);
			messageToSend = _generateMiningNotify(false);
		}
		_latestJobTp = std::chrono::steady_clock::now();
		for (const auto &worker : _workers) {
			if (write(worker.second->fileDescriptor, messageToSend.c_str(), messageToSend.size()) < 0)
				LOGMSG("Could not notify " << worker.second->str());
		}
	}
}

void Pool::run() {
	addrinfo hints;
	addrinfo *result, *rp;
	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	LOGMSG("Binding to port " << configuration.options().poolPort << "...");
	if (getaddrinfo(NULL, std::to_string(configuration.options().poolPort).c_str(), &hints, &result) != 0) {
		ERRORMSG("Getaddrinfo failed, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	int poolFd, epollFd;
	epoll_event event, events[maxEvents];
	for (rp = result ; rp != NULL ; rp = rp->ai_next) {
		poolFd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (poolFd == -1)
			continue;
		int optval(1);
		if (setsockopt(poolFd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(decltype(optval))) < 0) // Allows to restart the Pool without delay, otherwise there will be an "Address Already in Use" error for some time
			ERRORMSG("Setsockopt could not set SO_REUSEADDR (safe to ignore)");
		if (bind(poolFd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(poolFd);
	}
	if (rp == NULL) {
		ERRORMSG("Unable to bind, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	freeaddrinfo(result);
	LOGMSG("Success, the Pool File Descriptor is " << poolFd);
	if (fcntl(poolFd, F_SETFL, fcntl(poolFd, F_GETFL, 0) | O_NONBLOCK) == -1) {
		ERRORMSG("Unable to make the socket non blocking, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	if (listen(poolFd, SOMAXCONN) == -1) {
		ERRORMSG("Unable to listen to socket, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	LOGMSG("Listening, max connections: " << SOMAXCONN);
	epollFd = epoll_create1(0);
	if (epollFd == -1) {
		ERRORMSG("Unable to create Epoll instance, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	event.data.fd = poolFd;
	event.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(epollFd, EPOLL_CTL_ADD, poolFd, &event) == -1) {
		ERRORMSG("Epoll_ctl failed, errno " << errno << " - " << std::strerror(errno));
		return;
	}
	memset(&events, 0, maxEvents*sizeof(epoll_event));
	
	_curlMain = curl_easy_init();
	_currentJobId = 0ULL;
	_fetchJob();
	if (_currentJobs.size() < 1) {
		ERRORMSG("Could not get a first job, check if Riecoin Core is running and your configuration");
		curl_easy_cleanup(_curlMain);
		return;
	}
	
	_startNewRound(_currentJobs.back().height);
	LOGMSG("Started first Round " << _rounds.back().id << ": Block " << _rounds.back().heightStart);
	
	_running = true;
	LOGMSG("Starting Stats updater...");
	_statsUpdater = std::thread(&Pool::_updateStats, this);
	while (_running) {
		// Update work
		_fetchJob();
		// Process messages from workers if any
		const int nEvents(epoll_wait(epollFd, events, maxEvents, 100));
		for (int i(0) ; i < nEvents ; i++) {
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
				LOGMSG("Connection on fd " << events[i].data.fd << " closed");
				close(events[i].data.fd);
				_removeWorker(events[i].data.fd);
				continue;
			}
			else if (events[i].data.fd == poolFd) { // New connection(s)
				while (_running) {
					sockaddr address;
					socklen_t addressLength(sizeof(address));
					int workerFd(accept(poolFd, &address, &addressLength));
					if (workerFd == -1) {
						if (errno != EAGAIN && errno != EWOULDBLOCK)
							ERRORMSG("Unable to process incoming connection(s), errno " << errno << " - " << std::strerror(errno));
						break;
					}
					const std::shared_ptr<Worker> newWorker(std::make_shared<Worker>());
					newWorker->fileDescriptor = workerFd;
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
					if (getnameinfo(&address, addressLength, hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
						ERRORMSG("Something went wrong with Getnameinfo, fd " << newWorker->fileDescriptor << ", errno " << errno << " - " << std::strerror(errno));
						close(newWorker->fileDescriptor);
						continue;
					}
					newWorker->ip = hbuf;
					try {newWorker->port = std::stoi(sbuf);}
					catch (...) {ERRORMSG("Unable to get port of worker from " << newWorker->ip); newWorker->port = 0U;}
					if (fcntl(newWorker->fileDescriptor, F_SETFL, fcntl(newWorker->fileDescriptor, F_GETFL, 0) | O_NONBLOCK) == -1) {
						ERRORMSG("Unable to make incoming socket non blocking, errno " << errno << " - " << std::strerror(errno));
						close(newWorker->fileDescriptor);
						continue;
					}
					event.data.fd = newWorker->fileDescriptor;
					event.events = EPOLLIN | EPOLLET;
					if (epoll_ctl(epollFd, EPOLL_CTL_ADD, newWorker->fileDescriptor, &event) == -1) {
						ERRORMSG("Epoll_ctl failed, errno " << errno << " - " << std::strerror(errno));
						close(newWorker->fileDescriptor);
						continue;
					}
					_workers[newWorker->fileDescriptor] = newWorker;
					{
						const std::lock_guard lock(_stateMutex);
						WorkerStats stats;
						stats.id = newWorker->id;
						stats.ip = newWorker->ip;
						stats.port = newWorker->port;
						stats.connectedAt = nowU64();
						_workerStats[newWorker->id] = std::move(stats);
					}
					_workerCount.fetch_add(1, std::memory_order_relaxed);
					LOGMSG("Accepted connection from new " << newWorker->str() << ". Workers: " << _workers.size());
				}
			}
			else { // Data to be processed
				std::shared_ptr<Worker> worker;
				try {
					worker = _workers.at(events[i].data.fd);
				}
				catch (...) {
					ERRORMSG("Could not find the worker with fd " << events[i].data.fd);
					close(events[i].data.fd);
					continue;
				}
				std::string receivedMessage;
				while (_running) { // Combine partial messages in this loop
					constexpr std::size_t bufferSize(2U*maxMessageLength);
					ssize_t count;
					char buffer[bufferSize];
					memset(&buffer, 0, bufferSize);
					count = read(events[i].data.fd, buffer, bufferSize - 1U);
					receivedMessage += buffer;
					if (receivedMessage.size() > maxMessageLength) { // Ignore unreasonably long message (possible bug)
						LOGMSG("Ignoring long message of " << receivedMessage.size() << " bytes and kicking " << worker->str());
						close(events[i].data.fd);
						_removeWorker(events[i].data.fd);
						break;
					}
					if (count == -1) { // Either message fully reconstructed, or something went wrong
						if (errno != EAGAIN && errno != EWOULDBLOCK) {
							close(events[i].data.fd);
							_removeWorker(events[i].data.fd);
							LOGMSG("Connection with " << worker->str() << " closed, errno " << errno << " - " << std::strerror(errno) << ". Workers: " << _workers.size());
							break;
						}
						// It is possible that multiple lines have to be treated at once. We need to process all of them.
						std::stringstream resultSS(receivedMessage);
						std::string line;
						while (std::getline(resultSS, line)) {
							const std::pair<std::string, bool> reply(_processMessage(std::make_pair(worker, line))); // Message to send and whether the worker should be disconnected
							if (write(worker->fileDescriptor, reply.first.c_str(), reply.first.size()) == -1)
								ERRORMSG("Could not send message to " << worker->str() << ": " << reply.first);
							if (reply.second) {
								LOGMSG("Disconnecting " << worker->str());
								close(events[i].data.fd);
								_removeWorker(events[i].data.fd);
								break;
							}
						}
						break;
					}
					else if (count == 0) { // The worker disconected
						close(events[i].data.fd);
						_removeWorker(events[i].data.fd);
						LOGMSG(worker->str() << " disconected. Workers: " << _workers.size());
						break;
					}
				}
			}
		}
		for (auto it(_workers.cbegin()); it != _workers.cend();) {
			const std::string disconnectMessage("{\"id\": null, \"method\": \"client.show_message\", \"params\": [\"Worker disconnected due to inactivity\"]}\n"s);
			if (timeSince(it->second->latestShareTp) > maxInactivityTime) {
				LOGMSG("Disconnecting inactive " << it->second->str());
				const ssize_t bytesWritten = write(
					it->second->fileDescriptor,
					disconnectMessage.c_str(),
					disconnectMessage.size()
				);
				if (bytesWritten == -1)
					LOGMSG("Failed to send inactivity disconnect message: " << std::strerror(errno));
				close(it->second->fileDescriptor);
				const int fileDescriptor = it->first;
				++it;
				_removeWorker(fileDescriptor);
			}
			else
				it++;
		}
	}
	_statsUpdater.join();
	close(epollFd);
	close(poolFd);
	curl_easy_cleanup(_curlMain);
}
