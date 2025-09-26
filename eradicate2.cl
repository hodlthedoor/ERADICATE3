#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable

enum ModeFunction {
	Benchmark, ZeroBytes, Matching, Leading, Range, Mirror, Doubles, LeadingRange, Trailing
};

typedef struct {
	enum ModeFunction function;
	uchar data1[20];
	uchar data2[20];
} mode;

typedef struct __attribute__((packed)) {
	uchar salt[32];
	uchar hash[20];
	uint found;
} result;

__kernel void eradicate2_iterate(__global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_result_update(const uchar * const hash, __global result * const pResult, const uchar score, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_leading(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_benchmark(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_zerobytes(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_matching(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_trailing(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_range(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_leadingrange(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_mirror(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);
void eradicate2_score_doubles(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round);

__kernel void eradicate2_iterate(__global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	ethhash h = { .q = { ERADICATE2_INITHASH } };

	h.d[6] += deviceIndex;
	h.d[7] += get_global_id(0);
	h.d[8] += round;

	uchar original_salt[32];
	for (int i = 0; i < 32; i++) {
		original_salt[i] = h.b[21 + i];
	}

	sha3_keccakf(&h);

	ethhash h_create2 = { 0 };

	h_create2.b[0] = 0xff;

	h_create2.b[1] = 0xBA; h_create2.b[2] = 0x20; h_create2.b[3] = 0x3f; h_create2.b[4] = 0xFD;
	h_create2.b[5] = 0xB6; h_create2.b[6] = 0x72; h_create2.b[7] = 0x7c; h_create2.b[8] = 0x59;
	h_create2.b[9] = 0xe3; h_create2.b[10] = 0x1D; h_create2.b[11] = 0x73; h_create2.b[12] = 0xd6;
	h_create2.b[13] = 0x62; h_create2.b[14] = 0x90; h_create2.b[15] = 0xFF; h_create2.b[16] = 0xb4;
	h_create2.b[17] = 0x77; h_create2.b[18] = 0x28; h_create2.b[19] = 0xe4; h_create2.b[20] = 0xCb;

	for (int i = 0; i < 32; i++) {
		h_create2.b[21 + i] = original_salt[i];
	}

	h_create2.b[53] = 0x21; h_create2.b[54] = 0xc3; h_create2.b[55] = 0x5d; h_create2.b[56] = 0xbe;
	h_create2.b[57] = 0x1b; h_create2.b[58] = 0x34; h_create2.b[59] = 0x4a; h_create2.b[60] = 0x24;
	h_create2.b[61] = 0x88; h_create2.b[62] = 0xcf; h_create2.b[63] = 0x33; h_create2.b[64] = 0x21;
	h_create2.b[65] = 0xd6; h_create2.b[66] = 0xce; h_create2.b[67] = 0x54; h_create2.b[68] = 0x2f;
	h_create2.b[69] = 0x8e; h_create2.b[70] = 0x9f; h_create2.b[71] = 0x30; h_create2.b[72] = 0x55;
	h_create2.b[73] = 0x44; h_create2.b[74] = 0xff; h_create2.b[75] = 0x09; h_create2.b[76] = 0xe4;
	h_create2.b[77] = 0x99; h_create2.b[78] = 0x3a; h_create2.b[79] = 0x62; h_create2.b[80] = 0x31;
	h_create2.b[81] = 0x9a; h_create2.b[82] = 0x49; h_create2.b[83] = 0x7c; h_create2.b[84] = 0x1f;

	h_create2.b[85] ^= 0x01;

	sha3_keccakf(&h_create2);

	ethhash h_create = { 0 };
	h_create.b[0] = 0xd6;
	h_create.b[1] = 0x94;

	for (int i = 0; i < 20; i++) {
		h_create.b[2 + i] = h_create2.b[12 + i];
	}
	h_create.b[22] = 0x01;

	h_create.b[23] ^= 0x01;

	sha3_keccakf(&h_create);
	h = h_create;
	switch (pMode->function) {
	case Benchmark:
		eradicate2_score_benchmark(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case ZeroBytes:
		eradicate2_score_zerobytes(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Matching:
		eradicate2_score_matching(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Leading:
		eradicate2_score_leading(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Trailing:
		eradicate2_score_trailing(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Range:
		eradicate2_score_range(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Mirror:
		eradicate2_score_mirror(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case Doubles:
		eradicate2_score_doubles(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;

	case LeadingRange:
		eradicate2_score_leadingrange(h.b + 12, pResult, pMode, scoreMax, deviceIndex, round);
		break;
	}
}

void eradicate2_result_update(const uchar * const H, __global result * const pResult, const uchar score, const uchar scoreMax, const uint deviceIndex, const uint round) {
	if (score && score > scoreMax) {
		const uchar hasResult = atomic_inc(&pResult[score].found);

		if (hasResult == 0) {
			ethhash h = { .q = { ERADICATE2_INITHASH } };
			h.d[6] += deviceIndex;
			h.d[7] += get_global_id(0);
			h.d[8] += round;

			for (int i = 0; i < 32; ++i) {
				pResult[score].salt[i] = h.b[i + 21];
			}

			for (int i = 0; i < 20; ++i) {
				pResult[score].hash[i] = H[i];
			}
		}
	}
}

void eradicate2_score_leading(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		if ((hash[i] & 0xF0) >> 4 == pMode->data1[0]) {
			++score;
		} else {
			break;
		}

		if ((hash[i] & 0x0F) == pMode->data1[0]) {
			++score;
		} else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_benchmark(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_zerobytes(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		score += !hash[i];
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_matching(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		if (pMode->data1[i] > 0 && (hash[i] & pMode->data1[i]) == pMode->data2[i]) {
			++score;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_trailing(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 19; i > 0; --i) {
		if (pMode->data1[i] > 0 && (hash[i] & pMode->data1[i]) == pMode->data2[i]) {
			++score;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_range(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		const uchar first = (hash[i] & 0xF0) >> 4;
		const uchar second = (hash[i] & 0x0F);

		if (first >= pMode->data1[0] && first <= pMode->data2[0]) {
			++score;
		}

		if (second >= pMode->data1[0] && second <= pMode->data2[0]) {
			++score;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_leadingrange(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		const uchar first = (hash[i] & 0xF0) >> 4;
		const uchar second = (hash[i] & 0x0F);

		if (first >= pMode->data1[0] && first <= pMode->data2[0]) {
			++score;
		}
		else {
			break;
		}

		if (second >= pMode->data1[0] && second <= pMode->data2[0]) {
			++score;
		}
		else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_mirror(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 10; ++i) {
		const uchar leftLeft = (hash[9 - i] & 0xF0) >> 4;
		const uchar leftRight = (hash[9 - i] & 0x0F);

		const uchar rightLeft = (hash[10 + i] & 0xF0) >> 4;
		const uchar rightRight = (hash[10 + i] & 0x0F);

		if (leftRight != rightLeft) {
			break;
		}

		++score;

		if (leftLeft != rightRight) {
			break;
		}

		++score;
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}

void eradicate2_score_doubles(const uchar * const hash, __global result * const pResult, __global const mode * const pMode, const uchar scoreMax, const uint deviceIndex, const uint round) {
	const size_t id = get_global_id(0);
	int score = 0;

	for (int i = 0; i < 20; ++i) {
		if ((hash[i] == 0x00) || (hash[i] == 0x11) || (hash[i] == 0x22) || (hash[i] == 0x33) || (hash[i] == 0x44) || (hash[i] == 0x55) || (hash[i] == 0x66) || (hash[i] == 0x77) || (hash[i] == 0x88) || (hash[i] == 0x99) || (hash[i] == 0xAA) || (hash[i] == 0xBB) || (hash[i] == 0xCC) || (hash[i] == 0xDD) || (hash[i] == 0xEE) || (hash[i] == 0xFF)) {
			++score;
		}
		else {
			break;
		}
	}

	eradicate2_result_update(hash, pResult, score, scoreMax, deviceIndex, round);
}
