#include "CryptorSeedCBC.h"

// defines the class constructor
CryptorSeedCBC::CryptorSeedCBC()
{
	this->pLargeBuffer1 = 0;
	this->pLargeBuffer2 = 0;
	this->pNormalBuffer = 0;
	this->dwBufferSize = 0;
	this->pBuffer1 = 0;
	this->pBuffer2 = 0;
	this->pBuffer3 = 0;
	this->dword_0x1216C = 0;
}

BOOL CryptorSeedCBC::init(DWORD* dwSeed, DWORD* dwKey)
{
	int v19; // eax@3
	unsigned int v20; // edi@3
	unsigned int v21; // ebx@3
	unsigned int v22; // edx@3
	unsigned int v23; // eax@3
	unsigned int v24; // ST18_4@3
	unsigned int v25; // esi@3
	unsigned int v26; // ebx@3
	unsigned int v27; // edi@3
	unsigned int v28; // ebx@3
	int v29; // edx@3
	unsigned int v30; // esi@3
	unsigned int v31; // ST18_4@3
	int v32; // edx@3
	unsigned int v33; // edx@3
	unsigned int v34; // edx@3
	unsigned int v35; // ebx@3
	unsigned int v36; // edx@3
	unsigned int v37; // ST1C_4@3
	unsigned int v38; // edi@3
	unsigned int v39; // ebx@3
	int v40; // edx@3
	unsigned int v41; // ST18_4@3
	unsigned int v42; // edx@3
	unsigned int v43; // esi@3
	unsigned int v44; // ebx@3
	int v45; // edx@3
	unsigned int v46; // ST1C_4@3
	unsigned int v47; // edx@3
	unsigned int v48; // ebx@3
	unsigned int v49; // edx@3
	unsigned int v50; // edi@3
	unsigned int v51; // ebx@3
	int v52; // edx@3
	unsigned int v53; // esi@3
	unsigned int v54; // edx@3
	unsigned int v55; // ebx@3
	int v56; // ecx@3
	int v57; // edx@3
	unsigned int v58; // ST1C_4@3
	unsigned int v59; // esi@3
	unsigned int v60; // edi@3
	unsigned int v61; // ebx@3
	unsigned int v62; // ebx@3
	int v63; // ebx@3
	unsigned int v64; // ST18_4@3
	unsigned int v65; // ST1C_4@3
	unsigned int v66; // ebx@3
	int v67; // esi@3
	int v68; // edx@3
	unsigned int v69; // ebx@3
	unsigned int v70; // edx@3
	unsigned int v71; // ebx@3
	char result; // al@3
	int pCryptor; // [sp+14h] [bp-4h]@1
	unsigned int dwKey3; // [sp+20h] [bp+8h]@3
	unsigned int v75; // [sp+20h] [bp+8h]@3
	unsigned int v76; // [sp+20h] [bp+8h]@3
	unsigned int v77; // [sp+20h] [bp+8h]@3
	unsigned int dwKey1; // [sp+24h] [bp+Ch]@3
	int v79; // [sp+24h] [bp+Ch]@3
	int v80; // [sp+24h] [bp+Ch]@3
	unsigned int v81; // [sp+24h] [bp+Ch]@3
	unsigned int v82; // [sp+24h] [bp+Ch]@3
	unsigned int v83; // [sp+24h] [bp+Ch]@3
	unsigned int v84; // [sp+24h] [bp+Ch]@3
	int v85; // [sp+24h] [bp+Ch]@3

	// nulls the region of the cryptor structure this function will be filling out
	memset(&this->owKey1, 0, 0xB8);
	// validates the arguments
	if (dwSeed && dwKey)
	{
		// moves the key to the structure
		memcpy(&this->owKey1, dwKey, 16);
		// nulls some attributes
		this->dwBuffSizeMinus16 = 0;
		this->dword_0xB8 = 0;
		// moves the key to the structure
		memcpy(&this->owKey2, dwKey, 16);
		// dwKey is not used past this point
		// generates some sort of key via the seed
		// dwSeed is a 128 bit value (according to https://en.wikipedia.org/wiki/SEED)
		// so we have to take it four bytes at a time (since we are in 32 bit)
		DWORD dwKey1 = __KEY4__(dwSeed[0]);
		DWORD dwKey2 = __KEY4__(dwSeed[1]);
		DWORD dwKey3 = __KEY4__(dwSeed[2]);
		DWORD dwKey4 = __KEY4__(dwSeed[3]);
		// calculates the table offsets
		DWORD dwOffset1 = dwKey3 + dwKey1 + 1640531527;
		DWORD dwOffset2 = dwKey2 - dwKey4 - 1640531527;
		// constructs some dwords and saves them to the structure
		this->dword_0x14 = dword_AF8C00[FIRST_BYTE(dwKey3 + dwKey1 + 71)] ^ dword_AF9000[SECOND_BYTE(dwOffset1)] ^ dword_AF9400[THIRD_BYTE(dwOffset1)] ^ dword_AF9800[FOURTH_BYTE(dwOffset1)];
		this->dword_0x18 = dword_AF8C00[FIRST_BYTE(dwKey2 - dwKey4 - 71)] ^ dword_AF9000[SECOND_BYTE(dwOffset2)] ^ dword_AF9400[THIRD_BYTE(dwOffset2)] ^ dword_AF9800[FOURTH_BYTE(dwOffset2)];


		v79 = (dwKey2 >> 8) ^ (dwKey1 << 24);
		v20 = (dwKey1 >> 8) ^ (dwKey2 << 24);
		v21 = v79 - dwKey4 + 1013904243;

		// constructs some dwords and saves them to the structure
		this->dword_0x1C = dword_AF8C00[FIRST_BYTE(v20 + dwKey3 - 115)] ^ dword_AF9000[SECOND_BYTE(v20 + dwKey3 + 3213)] ^ dword_AF9400[THIRD_BYTE(v20 + dwKey3 - 1013904243)] ^ dword_AF9800[FOURTH_BYTE(v20 + dwKey3 - 1013904243)];
		this->dword_0x20 = dword_AF8C00[FIRST_BYTE(v79 - dwKey4 + 115)] ^ dword_AF9000[SECOND_BYTE(v21)] ^ dword_AF9400[THIRD_BYTE(v21)] ^ dword_AF9800[FOURTH_BYTE(v21)];

		v22 = ((dwKey3 << 8) ^ (dwKey4 >> 24)) + v20 - 2027808486;
		v23 = (dwKey4 << 8) ^ (dwKey3 >> 24);
		v24 = (dwKey3 << 8) ^ (dwKey4 >> 24);
		v25 = v79;
		v26 = v79 - v23 + 2027808486;

		this->dword_0x24 = dword_AF8C00[(unsigned __int8)(FOURTH_BYTE(dwKey4) + v20 + 26)] ^ dword_AF9000[SECOND_BYTE(v22)] ^ dword_AF9400[(unsigned __int8)(v22 >> 16)] ^ dword_AF9800[v22 >> 24];
		this->dword_0x28 = dword_AF8C00[(unsigned __int8)(v79 - FOURTH_BYTE(dwKey3) - 26)] ^ dword_AF9000[SECOND_BYTE(v26)] ^ dword_AF9400[(unsigned __int8)(v26 >> 16)] ^ dword_AF9800[v26 >> 24];

		v80 = (v20 >> 8) ^ (v79 << 24);
		v27 = (v25 >> 8) ^ (v20 << 24);
		v28 = v27 - v23 - 239350324;
		v29 = v80 + v24 + 239350324;

		this->dword_0x2C = dword_AF8C00[(unsigned __int8)(v80 + FOURTH_BYTE(dwKey4) + 52)] ^ dword_AF9000[SECOND_BYTE(v29)] ^ dword_AF9400[(unsigned __int8)((v80 + v24 + 239350324) >> 16)] ^ dword_AF9800[(v80 + v24 + 239350324) >> 24];
		this->dword_0x30 = dword_AF8C00[(unsigned __int8)(v27 - FOURTH_BYTE(dwKey3) - 52)] ^ dword_AF9000[SECOND_BYTE(v28)] ^ dword_AF9400[(unsigned __int8)(v28 >> 16)] ^ dword_AF9800[v28 >> 24];

		v30 = (v23 << 8) ^ (v24 >> 24);
		v31 = (v24 << 8) ^ (v23 >> 24);
		v32 = v31 + v80 + 478700647;

		this->dword_0x34 = dword_AF8C00[(unsigned __int8)(v31 + v80 + 103)] ^ dword_AF9000[SECOND_BYTE(v32)] ^ dword_AF9400[(unsigned __int8)((v31 + v80 + 478700647) >> 16)] ^ dword_AF9800[(v31 + v80 + 478700647) >> 24];
		this->dword_0x38 = dword_AF8C00[(unsigned __int8)(v27 - v30 - 103)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v27 - v30 - 25703) >> 8)] ^ dword_AF9400[(unsigned __int8)((v27 - v30 - 478700647) >> 16)] ^ dword_AF9800[(v27 - v30 - 478700647) >> 24];

		v33 = ((unsigned __int64)(unsigned int)v80 >> 8) ^ (v27 << 24);
		v75 = v33;
		v81 = (v27 >> 8) ^ (v80 << 24);
		v34 = v31 + v33 + 957401293;
		v35 = v81 - v30 - 957401293;

		this->dword_0x3C = dword_AF8C00[(unsigned __int8)v34] ^ dword_AF9000[SECOND_BYTE(v34)] ^ dword_AF9400[(unsigned __int8)(v34 >> 16)] ^ dword_AF9800[v34 >> 24];
		this->dword_0x40 = dword_AF8C00[(unsigned __int8)(v81 - v30 + 51)] ^ dword_AF9000[SECOND_BYTE(v35)] ^ dword_AF9400[(unsigned __int8)(v35 >> 16)] ^ dword_AF9800[v35 >> 24];

		v36 = ((v31 << 8) ^ (v30 >> 24)) + v75 + 1914802585;
		v37 = (v31 << 8) ^ (v30 >> 24);
		v38 = (v30 << 8) ^ (v31 >> 24);
		v39 = v81 - v38 - 1914802585;

		this->dword_0x44 = dword_AF8C00[(unsigned __int8)(FOURTH_BYTE(v30) + v75 - 103)] ^ dword_AF9000[SECOND_BYTE(v36)] ^ dword_AF9400[(unsigned __int8)(v36 >> 16)] ^ dword_AF9800[v36 >> 24];
		this->dword_0x48 = dword_AF8C00[(unsigned __int8)(v81 - FOURTH_BYTE(v31) + 103)] ^ dword_AF9000[SECOND_BYTE(v39)] ^ dword_AF9400[(unsigned __int8)(v39 >> 16)] ^ dword_AF9800[v39 >> 24];

		v40 = (v75 >> 8) ^ (v81 << 24);
		v41 = v40;
		v42 = v37 - 465362127 + v40;
		v43 = (v81 >> 8) ^ (v75 << 24);
		v44 = v43 - v38 + 465362127;

		this->dword_0x4C = dword_AF8C00[(unsigned __int8)v42] ^ dword_AF9000[SECOND_BYTE(v42)] ^ dword_AF9400[(unsigned __int8)(v42 >> 16)] ^ dword_AF9800[v42 >> 24];
		this->dword_0x50 = dword_AF8C00[(unsigned __int8)(SECOND_BYTE(v81) - v38 - 49)] ^ dword_AF9000[SECOND_BYTE(v44)] ^ dword_AF9400[(unsigned __int8)(v44 >> 16)] ^ dword_AF9800[v44 >> 24];

		v45 = (v37 << 8) ^ (v38 >> 24);
		v82 = v45;
		v46 = (v38 << 8) ^ (v37 >> 24);
		v47 = v41 + v45 - 930724254;
		v48 = v43 - v46 + 930724254;

		this->dword_0x54 = dword_AF8C00[(unsigned __int8)v47] ^ dword_AF9000[SECOND_BYTE(v47)] ^ dword_AF9400[(unsigned __int8)(v47 >> 16)] ^ dword_AF9800[v47 >> 24];
		this->dword_0x58 = dword_AF8C00[(unsigned __int8)(v43 - v46 - 98)] ^ dword_AF9000[SECOND_BYTE(v48)] ^ dword_AF9400[(unsigned __int8)(v48 >> 16)] ^ dword_AF9800[v48 >> 24];

		v49 = ((v41 >> 8) ^ (v43 << 24)) + v82 - 1861448508;
		v50 = (v43 >> 8) ^ (v41 << 24);
		v51 = v50 - v46 + 1861448508;

		this->dword_0x5C = dword_AF8C00[(unsigned __int8)(SECOND_BYTE(v41) + v82 - 60)] ^ dword_AF9000[SECOND_BYTE(v49)] ^ dword_AF9400[(unsigned __int8)(v49 >> 16)] ^ dword_AF9800[v49 >> 24];
		this->dword_0x60 = dword_AF8C00[(unsigned __int8)(SECOND_BYTE(v43) - v46 + 60)] ^ dword_AF9000[SECOND_BYTE(v51)] ^ dword_AF9400[(unsigned __int8)(v51 >> 16)] ^ dword_AF9800[v51 >> 24];

		v52 = (v82 << 8) ^ (v46 >> 24);
		v76 = v52;
		v53 = (v41 >> 8) ^ (v43 << 24);
		v83 = (v46 << 8) ^ (v82 >> 24);
		v54 = v53 + v52 + 572070280;
		v55 = v50 - v83 - 572070280;

		this->dword_0x64 = dword_AF8C00[(unsigned __int8)v54] ^ dword_AF9000[SECOND_BYTE(v54)] ^ dword_AF9400[(unsigned __int8)(v54 >> 16)] ^ dword_AF9800[v54 >> 24];
		this->dword_0x68 = dword_AF8C00[(unsigned __int8)(v50 - v83 + 120)] ^ dword_AF9000[SECOND_BYTE(v55)] ^ dword_AF9400[(unsigned __int8)(v55 >> 16)] ^ dword_AF9800[v55 >> 24];

		v56 = (v53 >> 8) ^ (v50 << 24);
		v57 = v56 + v76 + 1144140559;
		v58 = (v53 >> 8) ^ (v50 << 24);
		v59 = (v50 >> 8) ^ (v53 << 24);
		v60 = v83;
		v61 = v59 - v83 - 1144140559;

		this->dword_0x6C = dword_AF8C00[(unsigned __int8)(v56 + v76 + 15)] ^ dword_AF9000[SECOND_BYTE(v57)] ^ dword_AF9400[(unsigned __int8)((v56 + v76 + 1144140559) >> 16)] ^ dword_AF9800[(v56 + v76 + 1144140559) >> 24];
		this->dword_0x70 = dword_AF8C00[(unsigned __int8)(v59 - v83 - 15)] ^ dword_AF9000[SECOND_BYTE(v61)] ^ dword_AF9400[(unsigned __int8)(v61 >> 16)] ^ dword_AF9800[v61 >> 24];

		v84 = (v76 << 8) ^ (v83 >> 24);
		v77 = (v60 << 8) ^ (v76 >> 24);
		v62 = v59 - v77 + 2006686179;

		this->dword_0x74 = dword_AF8C00[(unsigned __int8)(v84 + v58 + 29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v84 + v58 + 26141) >> 8)] ^ dword_AF9400[(unsigned __int8)((v84 + v58 - 2006686179) >> 16)] ^ dword_AF9800[(v84 + v58 - 2006686179) >> 24];
		this->dword_0x78 = dword_AF8C00[(unsigned __int8)(v59 - v77 - 29)] ^ dword_AF9000[SECOND_BYTE(v62)] ^ dword_AF9400[(unsigned __int8)(v62 >> 16)] ^ dword_AF9800[v62 >> 24];

		v63 = (v59 >> 8) ^ (v58 << 24);
		v64 = (v58 >> 8) ^ (v59 << 24);
		v65 = v63;
		v66 = v63 - v77 - 281594938;

		this->dword_0x7C = dword_AF8C00[(unsigned __int8)(v84 + v64 + 58)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v84 + v64 - 13254) >> 8)] ^ dword_AF9400[(unsigned __int8)((v84 + v64 + 281594938) >> 16)] ^ dword_AF9800[(v84 + v64 + 281594938) >> 24];
		this->dword_0x80 = dword_AF8C00[(unsigned __int8)v66] ^ dword_AF9000[SECOND_BYTE(v66)] ^ dword_AF9400[(unsigned __int8)(v66 >> 16)] ^ dword_AF9800[v66 >> 24];

		v67 = (v84 << 8) ^ (v77 >> 24);
		v85 = (v77 << 8) ^ (v84 >> 24);
		v68 = v67 + v64 + 563189875;
		v69 = v65 - v85 - 563189875;

		this->dword_0x84 = dword_AF8C00[(unsigned __int8)(v67 + v64 + 115)] ^ dword_AF9000[SECOND_BYTE(v68)] ^ dword_AF9400[(unsigned __int8)((v67 + v64 + 563189875) >> 16)] ^ dword_AF9800[(v67 + v64 + 563189875) >> 24];
		this->dword_0x88 = dword_AF8C00[(unsigned __int8)(v65 - v85 - 115)] ^ dword_AF9000[SECOND_BYTE(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];

		v70 = v67 + ((v64 >> 8) ^ (v65 << 24)) + 1126379749;
		v71 = ((v65 >> 8) ^ (v64 << 24)) - v85 - 1126379749;

		this->dword_0x8C = dword_AF8C00[(unsigned __int8)(v67 + SECOND_BYTE(v64) - 27)] ^ dword_AF9000[SECOND_BYTE(v70)] ^ dword_AF9400[(unsigned __int8)(v70 >> 16)] ^ dword_AF9800[v70 >> 24];
		this->dword_0x90 = dword_AF8C00[(unsigned __int8)v71] ^ dword_AF9000[SECOND_BYTE(v71)] ^ dword_AF9400[(unsigned __int8)(v71 >> 16)] ^ dword_AF9800[v71 >> 24];
		// function succeeded
		return TRUE;
	}
	// function failed
	return FALSE;
}

// initializes the classes buffers
PVOID CryptorSeedCBC::buffer(DWORD dwSize)
{
	// zeroes out the oword_0x94 attribute by 16 bytes
	memset(&this->oword_0x94, 0, 16);
	// zeroes out the oword_0xA8 attribute by 16 bytes
	memset(&this->oword_0xA8, 0, 16);
	// zeroes out the dwBuffSizeMinus16 attribute by 4 bytes
	this->dwBuffSizeMinus16 = 0;
	// zeroes out the dword_0xB8 attribute by 4 bytes
	this->dword_0xB8 = 0;
	// moves the key set in ::init to the owKey1 attribute (this is also performed in ::init)
	memcpy(&this->owKey1, &this->owKey2, 16);
	// validates the size
	// if teh size is greater than 0x2000 we create buffers on the heap
	// else we use the buffer attributes of the class
	if (dwSize >= 0x2000)
	{
		// increments the size by 0x10
		dwSize += 0x10;
		// compares the size to the size set on the class
		// if the already created buffer are larger then needed
		// we return pointers to the already created buffers
		// else we allocate new buffers
		if (this->dwBufferSize < dwSize)
		{
			// checks if the buffer is already allocated
			if (this->pLargeBuffer1)
			{
				// frees the buffer
				free(this->pLargeBuffer1);
				// nulls the attribute
				this->pLargeBuffer1 = 0;
			}
			// checks if the buffer is already allocated
			if (this->pLargeBuffer2)
			{
				// frees the buffer
				free(this->pLargeBuffer2);
				// nulls the attribute
				this->pLargeBuffer2 = 0;
			}
			// checks if the buffer is already allocated
			if (this->pNormalBuffer)
			{
				// frees the buffer
				free(this->pNormalBuffer);
				// nulls the attribute
				this->pNormalBuffer = 0;
			}
			// constructs the buffer with the size of the decrypted data
			// all this does is multiple the data size plus 10 by 4 (the rest doesn't matter, since it's rarely used) 
			this->pLargeBuffer1 = malloc(4 * dwSize | -((unsigned __int64)(unsigned int)dwSize >> 30 != 0));
			this->pLargeBuffer2 = malloc(4 * dwSize | -((unsigned __int64)(unsigned int)dwSize >> 30 != 0));
			// creates a buffer of the data size plus 10
			this->pNormalBuffer = malloc(dwSize);
			// sets the buffer size attribute
			this->dwBufferSize = dwSize;
		}
		// returns pointers to already created buffers that are larger than needed
		// sets the buffer used for decryption to the already heap allocated
		this->pBuffer1 = this->pLargeBuffer1;
		// sets the buffer used for decryption to the already heap allocated
		this->pBuffer2 = this->pLargeBuffer2;
		// sets the normal buffer used for decryption to the already heap allocated
		this->pBuffer3 = this->pNormalBuffer;
		// zeroes out an attribute
		this->dword_0x1216C = 0;
		// returns an address to an allocated buffer of the data size plus 10
		return this->pNormalBuffer;
	}
	// since the data size is small enough we can use various attributes of the class structure as a buffer
	// sets the buffer used for decryption to the address of the corrosponding buffer attribute
	this->pBuffer1 = &this->Buffer1;
	// sets the buffer used for decryption to the address of the corrosponding buffer attribute
	this->pBuffer2 = &this->Buffer2;
	// sets the normal buffer used for decryption to the already heap allocated
	this->pBuffer3 = &this->Buffer3;
	// zeroes out an attribute
	this->dword_0x1216C = 0;
	// returns an address to a buffer attribute
	return &this->Buffer3;
}

// decrypts a key (pilfered from ida)
BOOL CryptorSeedCBC::sub_8ACC60(PBYTE pKey, PBYTE pData, PBYTE pBuff)
{
	int v3; // edx@1
	int v4; // ebx@1
	int v5; // esi@1
	int v6; // edi@1
	int v7; // eax@1
	unsigned int v9; // ebx@1
	int v10; // edx@1
	unsigned int v11; // ST14_4@1
	int v12; // ebx@1
	int v13; // edx@1
	int v14; // ecx@1
	unsigned int v15; // ebx@1
	int v16; // edx@1
	int v17; // ebx@1
	int v18; // ecx@1
	unsigned int v19; // ST0C_4@1
	int v20; // esi@1
	unsigned int v21; // esi@1
	int v22; // ebx@1
	int v23; // ecx@1
	unsigned int v24; // ebx@1
	int v25; // edx@1
	int v26; // ecx@1
	int v27; // ST14_4@1
	int v28; // ebx@1
	int v29; // ecx@1
	unsigned int v30; // ebx@1
	int v31; // edx@1
	int v32; // ecx@1
	int v33; // esi@1
	int v34; // edi@1
	int v35; // ebx@1
	int v36; // ecx@1
	unsigned int v37; // ebx@1
	int v38; // edx@1
	int v39; // ecx@1
	int v40; // ST14_4@1
	int v41; // ebx@1
	int v42; // ecx@1
	unsigned int v43; // ebx@1
	int v44; // edx@1
	int v45; // ecx@1
	int v46; // esi@1
	int v47; // edi@1
	int v48; // ebx@1
	int v49; // ecx@1
	unsigned int v50; // ebx@1
	int v51; // edx@1
	int v52; // ecx@1
	int v53; // ST14_4@1
	int v54; // ebx@1
	int v55; // ecx@1
	unsigned int v56; // ebx@1
	int v57; // edx@1
	int v58; // ecx@1
	int v59; // edi@1
	int v60; // esi@1
	int v61; // ebx@1
	int v62; // ecx@1
	unsigned int v63; // ebx@1
	int v64; // edx@1
	int v65; // ecx@1
	int v66; // ST14_4@1
	int v67; // ebx@1
	int v68; // ecx@1
	unsigned int v69; // ebx@1
	int v70; // edx@1
	int v71; // ecx@1
	int v72; // esi@1
	int v73; // edi@1
	int v74; // ebx@1
	int v75; // ecx@1
	unsigned int v76; // ebx@1
	int v77; // edx@1
	int v78; // ecx@1
	int v79; // ST14_4@1
	int v80; // ebx@1
	int v81; // ecx@1
	unsigned int v82; // ebx@1
	int v83; // edx@1
	int v84; // ecx@1
	int v85; // esi@1
	int v86; // edi@1
	int v87; // ebx@1
	int v88; // ecx@1
	unsigned int v89; // ebx@1
	int v90; // edx@1
	int v91; // ecx@1
	int v92; // ST14_4@1
	int v93; // ebx@1
	int v94; // ecx@1
	unsigned int v95; // ebx@1
	int v96; // edx@1
	int v97; // ecx@1
	int v98; // esi@1
	int v99; // edi@1
	int v100; // ebx@1
	int v101; // ecx@1
	unsigned int v102; // ebx@1
	int v103; // edx@1
	int v104; // ecx@1
	int v105; // ST14_4@1
	int v106; // ebx@1
	int v107; // ecx@1
	unsigned int v108; // ebx@1
	int v109; // edx@1
	int v110; // ecx@1
	int v111; // esi@1
	int v112; // edi@1
	int v113; // ebx@1
	int v114; // ecx@1
	unsigned int v115; // ebx@1
	int v116; // edx@1
	int v117; // ecx@1
	int v118; // edx@1
	int v119; // eax@1
	int v120; // eax@1
	int v121; // ebx@1
	int v122; // eax@1
	int v123; // eax@1
	unsigned int result; // eax@1
	unsigned int v125; // [sp+20h] [bp+8h]@1
	int v126; // [sp+20h] [bp+8h]@1
	int v127; // [sp+20h] [bp+8h]@1
	int v128; // [sp+20h] [bp+8h]@1
	int v129; // [sp+20h] [bp+8h]@1
	int v130; // [sp+20h] [bp+8h]@1
	int v131; // [sp+20h] [bp+8h]@1
	int v132; // [sp+20h] [bp+8h]@1

	v3 = *(DWORD*)(pData + 8);
	v4 = v3;
	v5 = *(DWORD*)pData;
	v6 = *(DWORD*)(pData + 4);
	v7 = *(DWORD*)(pData + 12);
	v3 = __ROL4__(v3, 8);
	v4 = __ROR4__(v4, 8);
	v9 = v3 & 0xFF00FF | v4 & 0xFF00FF00;
	v10 = v7;
	v7 = __ROL4__(v7, 8);
	v10 = __ROR4__(v10, 8);
	v11 = v9;
	v12 = v9 ^ this->dword_0x8C;
	v125 = v7 & 0xFF00FF | v10 & 0xFF00FF00;
	v13 = v125 ^ v12 ^ this->dword_0x90;
	v14 = dword_AF8C00[(unsigned __int8)(v125 ^ v12 ^ (BYTE)this->dword_0x90)] ^ dword_AF9000[SECOND_BYTE(v13)] ^ dword_AF9400[(unsigned __int8)((v125 ^ v12 ^ this->dword_0x90) >> 16)] ^ dword_AF9800[(v125 ^ v12 ^ this->dword_0x90) >> 24];
	v15 = v14 + v12;
	v16 = dword_AF8C00[(unsigned __int8)v15] ^ dword_AF9000[SECOND_BYTE(v15)] ^ dword_AF9400[(unsigned __int8)(v15 >> 16)] ^ dword_AF9800[v15 >> 24];
	v17 = __ROR4__(v5, 8);
	v5 = __ROL4__(v5, 8);
	v18 = dword_AF8C00[(unsigned __int8)(v16 + v14)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v16 + v14) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v16 + v14) >> 16)] ^ dword_AF9800[(unsigned int)(v16 + v14) >> 24];
	v19 = (v18 + v16) ^ (v5 & 0xFF00FF | v17 & 0xFF00FF00);
	v20 = __ROR4__(v6, 8);
	v6 = __ROL4__(v6, 8);
	v21 = v18 ^ (v6 & 0xFF00FF | v20 & 0xFF00FF00);
	v22 = v19 ^ this->dword_0x84;
	v23 = dword_AF8C00[(unsigned __int8)(v21 ^ v22 ^ (BYTE)this->dword_0x88)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v21 ^ v22 ^ (WORD)this->dword_0x88) >> 8)] ^ dword_AF9400[(unsigned __int8)((v21 ^ v22 ^ this->dword_0x88) >> 16)] ^ dword_AF9800[(v21 ^ v22 ^ this->dword_0x88) >> 24];
	v24 = v23 + v22;
	v25 = dword_AF8C00[(unsigned __int8)v24] ^ dword_AF9000[SECOND_BYTE(v24)] ^ dword_AF9400[(unsigned __int8)(v24 >> 16)] ^ dword_AF9800[v24 >> 24];
	v26 = dword_AF8C00[(unsigned __int8)(v25 + v23)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v25 + v23) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v25 + v23) >> 16)] ^ dword_AF9800[(unsigned int)(v25 + v23) >> 24];
	v126 = v26 ^ v125;
	v27 = (v26 + v25) ^ v11;
	v28 = v27 ^ *(DWORD*)((__int64)this + 124);
	v29 = dword_AF8C00[(unsigned __int8)(v126 ^ v28 ^ *(BYTE*)((__int64)this + 128))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v126 ^ v28 ^ *(WORD*)((__int64)this + 128)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v126 ^ (unsigned int)v28 ^ *(DWORD*)((__int64)this + 128)) >> 16)] ^ dword_AF9800[(v126 ^ (unsigned int)v28 ^ *(DWORD*)((__int64)this + 128)) >> 24];
	v30 = v29 + v28;
	v31 = dword_AF8C00[(unsigned __int8)v30] ^ dword_AF9000[SECOND_BYTE(v30)] ^ dword_AF9400[(unsigned __int8)(v30 >> 16)] ^ dword_AF9800[v30 >> 24];
	v32 = dword_AF8C00[(unsigned __int8)(v31 + v29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v31 + v29) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v31 + v29) >> 16)] ^ dword_AF9800[(unsigned int)(v31 + v29) >> 24];
	v33 = v32 ^ v21;
	v34 = (v32 + v31) ^ v19;
	v35 = v34 ^ *(DWORD*)((__int64)this + 116);
	v36 = dword_AF8C00[(unsigned __int8)(v33 ^ v35 ^ *(BYTE*)((__int64)this + 120))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v33 ^ v35 ^ *(WORD*)((__int64)this + 120)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v33 ^ (unsigned int)v35 ^ *(DWORD*)((__int64)this + 120)) >> 16)] ^ dword_AF9800[(v33 ^ (unsigned int)v35 ^ *(DWORD*)((__int64)this + 120)) >> 24];
	v37 = v36 + v35;
	v38 = dword_AF8C00[(unsigned __int8)v37] ^ dword_AF9000[SECOND_BYTE(v37)] ^ dword_AF9400[(unsigned __int8)(v37 >> 16)] ^ dword_AF9800[v37 >> 24];
	v39 = dword_AF8C00[(unsigned __int8)(v38 + v36)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v38 + v36) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v38 + v36) >> 16)] ^ dword_AF9800[(unsigned int)(v38 + v36) >> 24];
	v127 = v39 ^ v126;
	v40 = (v39 + v38) ^ v27;
	v41 = v40 ^ *(DWORD*)((__int64)this + 108);
	v42 = dword_AF8C00[(unsigned __int8)(v127 ^ v41 ^ *(BYTE*)((__int64)this + 112))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v127 ^ v41 ^ *(WORD*)((__int64)this + 112)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v127 ^ (unsigned int)v41 ^ *(DWORD*)((__int64)this + 112)) >> 16)] ^ dword_AF9800[(v127 ^ (unsigned int)v41 ^ *(DWORD*)((__int64)this + 112)) >> 24];
	v43 = v42 + v41;
	v44 = dword_AF8C00[(unsigned __int8)v43] ^ dword_AF9000[SECOND_BYTE(v43)] ^ dword_AF9400[(unsigned __int8)(v43 >> 16)] ^ dword_AF9800[v43 >> 24];
	v45 = dword_AF8C00[(unsigned __int8)(v44 + v42)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v44 + v42) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v44 + v42) >> 16)] ^ dword_AF9800[(unsigned int)(v44 + v42) >> 24];
	v46 = v45 ^ v33;
	v47 = (v45 + v44) ^ v34;
	v48 = v47 ^ *(DWORD*)((__int64)this + 100);
	v49 = dword_AF8C00[(unsigned __int8)(v46 ^ v48 ^ *(BYTE*)((__int64)this + 104))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v46 ^ v48 ^ *(WORD*)((__int64)this + 104)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v46 ^ (unsigned int)v48 ^ *(DWORD*)((__int64)this + 104)) >> 16)] ^ dword_AF9800[(v46 ^ (unsigned int)v48 ^ *(DWORD*)((__int64)this + 104)) >> 24];
	v50 = v49 + v48;
	v51 = dword_AF8C00[(unsigned __int8)v50] ^ dword_AF9000[SECOND_BYTE(v50)] ^ dword_AF9400[(unsigned __int8)(v50 >> 16)] ^ dword_AF9800[v50 >> 24];
	v52 = dword_AF8C00[(unsigned __int8)(v51 + v49)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v51 + v49) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v51 + v49) >> 16)] ^ dword_AF9800[(unsigned int)(v51 + v49) >> 24];
	v128 = v52 ^ v127;
	v53 = (v52 + v51) ^ v40;
	v54 = v53 ^ *(DWORD*)((__int64)this + 92);
	v55 = dword_AF8C00[(unsigned __int8)(v128 ^ v54 ^ *(BYTE*)((__int64)this + 96))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v128 ^ v54 ^ *(WORD*)((__int64)this + 96)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v128 ^ (unsigned int)v54 ^ *(DWORD*)((__int64)this + 96)) >> 16)] ^ dword_AF9800[(v128 ^ (unsigned int)v54 ^ *(DWORD*)((__int64)this + 96)) >> 24];
	v56 = v55 + v54;
	v57 = dword_AF8C00[(unsigned __int8)v56] ^ dword_AF9000[SECOND_BYTE(v56)] ^ dword_AF9400[(unsigned __int8)(v56 >> 16)] ^ dword_AF9800[v56 >> 24];
	v58 = dword_AF8C00[(unsigned __int8)(v57 + v55)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v57 + v55) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v57 + v55) >> 16)] ^ dword_AF9800[(unsigned int)(v57 + v55) >> 24];
	v59 = (v58 + v57) ^ v47;
	v60 = v58 ^ v46;
	v61 = v59 ^ *(DWORD*)((__int64)this + 84);
	v62 = dword_AF8C00[(unsigned __int8)(v60 ^ v61 ^ *(BYTE*)((__int64)this + 88))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v60 ^ v61 ^ *(WORD*)((__int64)this + 88)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v60 ^ (unsigned int)v61 ^ *(DWORD*)((__int64)this + 88)) >> 16)] ^ dword_AF9800[(v60 ^ (unsigned int)v61 ^ *(DWORD*)((__int64)this + 88)) >> 24];
	v63 = v62 + v61;
	v64 = dword_AF8C00[(unsigned __int8)v63] ^ dword_AF9000[SECOND_BYTE(v63)] ^ dword_AF9400[(unsigned __int8)(v63 >> 16)] ^ dword_AF9800[v63 >> 24];
	v65 = dword_AF8C00[(unsigned __int8)(v64 + v62)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v64 + v62) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v64 + v62) >> 16)] ^ dword_AF9800[(unsigned int)(v64 + v62) >> 24];
	v129 = v65 ^ v128;
	v66 = (v65 + v64) ^ v53;
	v67 = v66 ^ *(DWORD*)((__int64)this + 76);
	v68 = dword_AF8C00[(unsigned __int8)(v129 ^ v67 ^ *(BYTE*)((__int64)this + 80))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v129 ^ v67 ^ *(WORD*)((__int64)this + 80)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v129 ^ (unsigned int)v67 ^ *(DWORD*)((__int64)this + 80)) >> 16)] ^ dword_AF9800[(v129 ^ (unsigned int)v67 ^ *(DWORD*)((__int64)this + 80)) >> 24];
	v69 = v68 + v67;
	v70 = dword_AF8C00[(unsigned __int8)v69] ^ dword_AF9000[SECOND_BYTE(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];
	v71 = dword_AF8C00[(unsigned __int8)(v70 + v68)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v70 + v68) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v70 + v68) >> 16)] ^ dword_AF9800[(unsigned int)(v70 + v68) >> 24];
	v72 = v71 ^ v60;
	v73 = (v71 + v70) ^ v59;
	v74 = v73 ^ *(DWORD*)((__int64)this + 68);
	v75 = dword_AF8C00[(unsigned __int8)(v72 ^ v74 ^ *(BYTE*)((__int64)this + 72))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v72 ^ v74 ^ *(WORD*)((__int64)this + 72)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v72 ^ (unsigned int)v74 ^ *(DWORD*)((__int64)this + 72)) >> 16)] ^ dword_AF9800[(v72 ^ (unsigned int)v74 ^ *(DWORD*)((__int64)this + 72)) >> 24];
	v76 = v75 + v74;
	v77 = dword_AF8C00[(unsigned __int8)v76] ^ dword_AF9000[SECOND_BYTE(v76)] ^ dword_AF9400[(unsigned __int8)(v76 >> 16)] ^ dword_AF9800[v76 >> 24];
	v78 = dword_AF8C00[(unsigned __int8)(v77 + v75)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v77 + v75) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v77 + v75) >> 16)] ^ dword_AF9800[(unsigned int)(v77 + v75) >> 24];
	v130 = v78 ^ v129;
	v79 = (v78 + v77) ^ v66;
	v80 = v79 ^ *(DWORD*)((__int64)this + 60);
	v81 = dword_AF8C00[(unsigned __int8)(v130 ^ v80 ^ *(BYTE*)((__int64)this + 64))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v130 ^ v80 ^ *(WORD*)((__int64)this + 64)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v130 ^ (unsigned int)v80 ^ *(DWORD*)((__int64)this + 64)) >> 16)] ^ dword_AF9800[(v130 ^ (unsigned int)v80 ^ *(DWORD*)((__int64)this + 64)) >> 24];
	v82 = v81 + v80;
	v83 = dword_AF8C00[(unsigned __int8)v82] ^ dword_AF9000[SECOND_BYTE(v82)] ^ dword_AF9400[(unsigned __int8)(v82 >> 16)] ^ dword_AF9800[v82 >> 24];
	v84 = dword_AF8C00[(unsigned __int8)(v83 + v81)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v83 + v81) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v83 + v81) >> 16)] ^ dword_AF9800[(unsigned int)(v83 + v81) >> 24];
	v85 = v84 ^ v72;
	v86 = (v84 + v83) ^ v73;
	v87 = v86 ^ *(DWORD*)((__int64)this + 52);
	v88 = dword_AF8C00[(unsigned __int8)(v85 ^ v87 ^ *(BYTE*)((__int64)this + 56))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v85 ^ v87 ^ *(WORD*)((__int64)this + 56)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v85 ^ (unsigned int)v87 ^ *(DWORD*)((__int64)this + 56)) >> 16)] ^ dword_AF9800[(v85 ^ (unsigned int)v87 ^ *(DWORD*)((__int64)this + 56)) >> 24];
	v89 = v88 + v87;
	v90 = dword_AF8C00[(unsigned __int8)v89] ^ dword_AF9000[SECOND_BYTE(v89)] ^ dword_AF9400[(unsigned __int8)(v89 >> 16)] ^ dword_AF9800[v89 >> 24];
	v91 = dword_AF8C00[(unsigned __int8)(v90 + v88)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v90 + v88) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v90 + v88) >> 16)] ^ dword_AF9800[(unsigned int)(v90 + v88) >> 24];
	v131 = v91 ^ v130;
	v92 = (v91 + v90) ^ v79;
	v93 = v92 ^ *(DWORD*)((__int64)this + 44);
	v94 = dword_AF8C00[(unsigned __int8)(v131 ^ v93 ^ *(BYTE*)((__int64)this + 48))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v131 ^ v93 ^ *(WORD*)((__int64)this + 48)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v131 ^ (unsigned int)v93 ^ *(DWORD*)((__int64)this + 48)) >> 16)] ^ dword_AF9800[(v131 ^ (unsigned int)v93 ^ *(DWORD*)((__int64)this + 48)) >> 24];
	v95 = v94 + v93;
	v96 = dword_AF8C00[(unsigned __int8)v95] ^ dword_AF9000[SECOND_BYTE(v95)] ^ dword_AF9400[(unsigned __int8)(v95 >> 16)] ^ dword_AF9800[v95 >> 24];
	v97 = dword_AF8C00[(unsigned __int8)(v96 + v94)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v96 + v94) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v96 + v94) >> 16)] ^ dword_AF9800[(unsigned int)(v96 + v94) >> 24];
	v98 = v97 ^ v85;
	v99 = (v97 + v96) ^ v86;
	v100 = v99 ^ *(DWORD*)((__int64)this + 36);
	v101 = dword_AF8C00[(unsigned __int8)(v98 ^ v100 ^ *(BYTE*)((__int64)this + 40))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v98 ^ v100 ^ *(WORD*)((__int64)this + 40)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v98 ^ (unsigned int)v100 ^ *(DWORD*)((__int64)this + 40)) >> 16)] ^ dword_AF9800[(v98 ^ (unsigned int)v100 ^ *(DWORD*)((__int64)this + 40)) >> 24];
	v102 = v101 + v100;
	v103 = dword_AF8C00[(unsigned __int8)v102] ^ dword_AF9000[SECOND_BYTE(v102)] ^ dword_AF9400[(unsigned __int8)(v102 >> 16)] ^ dword_AF9800[v102 >> 24];
	v104 = dword_AF8C00[(unsigned __int8)(v103 + v101)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v103 + v101) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v103 + v101) >> 16)] ^ dword_AF9800[(unsigned int)(v103 + v101) >> 24];
	v132 = v104 ^ v131;
	v105 = (v104 + v103) ^ v92;
	v106 = v105 ^ *(DWORD*)((__int64)this + 28);
	v107 = dword_AF8C00[(unsigned __int8)(v132 ^ v106 ^ *(BYTE*)((__int64)this + 32))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v132 ^ v106 ^ *(WORD*)((__int64)this + 32)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v132 ^ (unsigned int)v106 ^ *(DWORD*)((__int64)this + 32)) >> 16)] ^ dword_AF9800[(v132 ^ (unsigned int)v106 ^ *(DWORD*)((__int64)this + 32)) >> 24];
	v108 = v107 + v106;
	v109 = dword_AF8C00[(unsigned __int8)v108] ^ dword_AF9000[SECOND_BYTE(v108)] ^ dword_AF9400[(unsigned __int8)(v108 >> 16)] ^ dword_AF9800[v108 >> 24];
	v110 = dword_AF8C00[(unsigned __int8)(v109 + v107)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v109 + v107) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v109 + v107) >> 16)] ^ dword_AF9800[(unsigned int)(v109 + v107) >> 24];
	v111 = v110 ^ v98;
	v112 = (v110 + v109) ^ v99;
	v113 = v112 ^ *(DWORD*)((__int64)this + 20);
	v114 = dword_AF8C00[(unsigned __int8)(v111 ^ v113 ^ *(BYTE*)((__int64)this + 24))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v111 ^ v113 ^ *(WORD*)((__int64)this + 24)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v111 ^ (unsigned int)v113 ^ *(DWORD*)((__int64)this + 24)) >> 16)] ^ dword_AF9800[(v111 ^ (unsigned int)v113 ^ *(DWORD*)((__int64)this + 24)) >> 24];
	v115 = v114 + v113;
	v116 = dword_AF8C00[(unsigned __int8)v115] ^ dword_AF9000[SECOND_BYTE(v115)] ^ dword_AF9400[(unsigned __int8)(v115 >> 16)] ^ dword_AF9800[v115 >> 24];
	v117 = dword_AF8C00[(unsigned __int8)(v116 + v114)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v116 + v114) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v116 + v114) >> 16)] ^ dword_AF9800[(unsigned int)(v116 + v114) >> 24];
	v118 = (v117 + v116) ^ v105;
	v119 = v118;
	v118 = __ROL4__(v118, 8);
	v119 = __ROR4__(v119, 8);
	*(DWORD*)pBuff = v118 & 0xFF00FF | v119 & 0xFF00FF00;
	v120 = __ROR4__(v117 ^ v132, 8);
	v121 = __ROL4__(v117 ^ v132, 8);
	*(DWORD*)(pBuff + 4) = v121 & 0xFF00FF | v120 & 0xFF00FF00;
	v122 = __ROR4__(v112, 8);
	v112 = __ROL4__(v112, 8);
	*(DWORD*)(pBuff + 8) = v112 & 0xFF00FF | v122 & 0xFF00FF00;
	v123 = v111;
	v111 = __ROL4__(v111, 8);
	v123 = __ROR4__(v123, 8);
	result = v111 & 0xFF00FF | v123 & 0xFF00FF00;
	*(DWORD*)(pBuff + 0xC) = result;
	return result;
}

// does something
BOOL CryptorSeedCBC::something(DWORD* pData, DWORD dwSize, DWORD* pBuff, DWORD* pSize)
{
	// stores the size to be returned to the caller
	DWORD dwDataSize = 16;
	// validates the arguments
	if (pData && pBuff)
	{
		// sets an attribute
		this->dwBuffSizeMinus16 = dwSize - 16;
		// stores the key
		DWORD* pOwKey = (DWORD*)&this->owKey1;
		// validates the data (that it has blocks)
		if (dwSize >= 16)
		{
			// gets the amount of keys
			DWORD dwBlocks = dwSize / 16;
			// sets the output size
			dwDataSize = (dwBlocks + 1) * 16;
			// iterates through the keys
			do
			{
				// decrypts the keys
				CryptorSeedCBC::sub_8ACC60((DWORD)pData, (DWORD)pBuff);
				// xors with the key
				pBuff[0] ^= pOwKey[0];
				pBuff[1] ^= pOwKey[1];
				pBuff[2] ^= pOwKey[2];
				pBuff[3] ^= pOwKey[3];
				// sets the ow key pointer as a pointer to the new key
				pOwKey = pData;
				// gets the next block
				pData += 4;
				// gets the next block
				pBuff += 4;
				// decrements the block count
				dwBlocks--;
			} while (dwBlocks != 0);
		}
		// sets the output size
		*pSize = dwDataSize & 0xFFFFFFF0;
		// sets the structure key
		memcpy(&this->owKey1, (pData - 4), 16);
		// sets the structure key
		memcpy(&this->oword_0xA8, (pBuff - 4), 16);
		// function succeeded
		return TRUE;
	}
	// function failed
	return FALSE;
}

// copies the buffer
BOOL CryptorSeedCBC::sub_8AF3C0(PVOID pData, DWORD dwSize, PVOID pBuff)
{
	int v3 = 0;
	if (dwSize)
	{
		do
		{
			*(BYTE*)(v3 + (__int64)pBuff) = *(DWORD*)((__int64)pData + 4 * (v3 >> 2)) >> 8 * (v3 & 3);
			++v3;
		} while (v3 < dwSize);
	}
	return 1;
}

// decrypts the given data buffer
DWORD CryptorSeedCBC::decrypt(PVOID pData, DWORD dwSize)
{
	// creates some completely empty buffers and sets some attributes
	CryptorSeedCBC::buffer(dwSize);
	// zeroes out an attribute (this is already done in ::buffer)
	this->dword_0x1216C = 0;
	// validates the data size
	if (!(dwSize & 0xF))
	{
		// copies the data from the buffer to the new buffer
		memcpy(this->pBuffer1, pData, dwSize);
		// stores the size out put
		DWORD dwOutput;
		// decrypts
		CryptorSeedCBC::something((DWORD*)this->pBuffer1, dwSize, (DWORD*)this->pBuffer2, &dwOutput);
		DWORD buffSize = dwOutput / 4;
		// validates the output
		if ((((__int64)this->pBuffer2 + buffSize) * 4))
		{
			if ((this->byte_0xB7 - 1) <= 0xF)
			{
				if (this->byte_0xB7 != 0)
				{
					// zeros out a region
					memset((PVOID)((((__int64)this->pBuffer2 + buffSize) * 4) - this->byte_0xB7), 0, this->byte_0xB7);
					// zeros out a region
					memset((PVOID)((((__int64)this->pBuffer2 + buffSize) * 4) - this->byte_0xB7), 0, this->byte_0xB7 & 3);
				}
				// moves the decrypted data into buffer3
				CryptorSeedCBC::sub_8AF3C0(this->pBuffer2, dwOutput - this->byte_0xB7, this->pBuffer3);
				// checks the buff size
				if (dwOutput > this->byte_0xB7)
				{
					// sets the return value as the data size
					this->dword_0x1216C = (dwOutput - this->byte_0xB7);
				}
			}
		}
		// returns a pointer
		return this->dword_0x1216C;
	}
	// function failed
	return NULL;
}