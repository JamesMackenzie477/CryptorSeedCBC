#include <iostream>
#include "CryptorSeedCBC.h"

using namespace std;

// contains the encrypted file data
unsigned char EncryptedFile[] = {
	0x42, 0x03, 0x00, 0x00, 0xD6, 0xDB, 0xB5, 0x21, 0xA6, 0xCC, 0x25, 0x9E, 0xD1, 0xEA, 0xCA, 0xF0,
	0x9A, 0xCD, 0xF2, 0xDA, 0x01, 0x94, 0x3C, 0x99, 0x0B, 0x35, 0x51, 0xB5, 0xC5, 0x4F, 0x26, 0x2F,
	0x35, 0x5A, 0x47, 0x95, 0xE5, 0xBE, 0xC0, 0x78, 0xE2, 0xE8, 0x2F, 0x37, 0xE2, 0xBB, 0x91, 0x35,
	0xAB, 0xD6, 0xD2, 0x42, 0x7D, 0x95, 0x7C, 0x3D, 0x85, 0x95, 0xE2, 0x65, 0x1C, 0x96, 0xE7, 0x46,
	0xB1, 0x70, 0x73, 0x71, 0x0A, 0xAC, 0x35, 0xFC, 0xF8, 0xA0, 0x87, 0x53, 0x03, 0xA0, 0x6E, 0x48,
	0x85, 0x45, 0xCA, 0xAD, 0x28, 0x2F, 0x6F, 0x91, 0xC1, 0xAD, 0x8C, 0x41, 0xA9, 0x54, 0x33, 0x57,
	0x58, 0xC1, 0xFE, 0x0C, 0x63, 0xE6, 0x4A, 0x29, 0x0A, 0x57, 0x20, 0xBC, 0x21, 0x90, 0xC6, 0x13,
	0x90, 0x96, 0x4C, 0xF2, 0x96, 0x0B, 0xB8, 0x55, 0x6E, 0x77, 0x19, 0x97, 0xD7, 0x9E, 0x5B, 0x26,
	0xDC, 0x44, 0x9D, 0xFD, 0x3D, 0x14, 0x0E, 0xAB, 0xAF, 0x8F, 0x11, 0x6C, 0x08, 0x30, 0x64, 0x22,
	0xFF, 0xF1, 0x73, 0x92, 0x0B, 0x4D, 0x6D, 0xA4, 0x2A, 0x64, 0xBA, 0xBC, 0xFF, 0x0A, 0xA7, 0xD6,
	0x4F, 0x69, 0xB3, 0x46, 0xF3, 0xC3, 0xE1, 0xA5, 0x7C, 0x4A, 0xAA, 0x44, 0xE1, 0xD6, 0x7E, 0xE1,
	0x5B, 0x72, 0x53, 0xC2, 0x15, 0xFA, 0x02, 0x17, 0xDF, 0xEE, 0x3A, 0xD6, 0xE2, 0x79, 0x49, 0xC6,
	0x5B, 0x19, 0x57, 0xE2, 0x4B, 0x3B, 0xDD, 0xD4, 0x99, 0x93, 0xBF, 0x0C, 0x0A, 0x4C, 0x48, 0x96,
	0x90, 0x5A, 0x35, 0x44, 0x9E, 0x2B, 0x38, 0x0A, 0x23, 0xF0, 0xC9, 0x1B, 0x45, 0x56, 0x52, 0xC2,
	0x2B, 0xFB, 0x5C, 0x4A, 0x9C, 0x88, 0x4E, 0x75, 0xEF, 0x3D, 0xF4, 0x1E, 0x79, 0x3E, 0x84, 0x91,
	0xF4, 0xB4, 0x59, 0xA8, 0x02, 0xF2, 0xA7, 0x6B, 0xBE, 0x6E, 0xAA, 0x99, 0x80, 0x2C, 0x9E, 0xC5,
	0xD9, 0x7E, 0xE9, 0x59, 0x4E, 0x5F, 0x84, 0x21, 0xE5, 0xFE, 0x9E, 0x92, 0xEA, 0x65, 0x16, 0x34,
	0xF5, 0x47, 0xE9, 0x38, 0x08, 0xE6, 0xAD, 0x84, 0x43, 0x8F, 0x5B, 0xB3, 0xC3, 0x9E, 0x2C, 0x68,
	0x0F, 0x80, 0xF0, 0xF2, 0xFC, 0x83, 0x35, 0x14, 0x98, 0xFF, 0x22, 0x3A, 0xA0, 0x74, 0x2A, 0xD6,
	0x13, 0xB1, 0x54, 0x46, 0x94, 0x7A, 0x47, 0x2F, 0xA6, 0x35, 0xCD, 0x61, 0x70, 0x8F, 0x08, 0x10,
	0xD6, 0xAE, 0xAA, 0xEA, 0x1A, 0x28, 0x14, 0x6A, 0xB9, 0x70, 0xF6, 0x17, 0x5E, 0x05, 0xF7, 0xEF,
	0x5C, 0xB8, 0xB4, 0x23, 0x89, 0x99, 0x6A, 0x71, 0x46, 0x94, 0xDB, 0x7F, 0x5E, 0xBC, 0xDB, 0xD5,
	0xD4, 0xA9, 0x85, 0x61, 0xCE, 0xEF, 0xC9, 0x51, 0x74, 0x59, 0x98, 0x2A, 0xA0, 0xD8, 0x80, 0x66,
	0xFD, 0x66, 0x9B, 0xA2, 0xBC, 0x96, 0xCB, 0xB1, 0x0A, 0xEE, 0x7C, 0x46, 0xD7, 0xB5, 0xE6, 0xA0,
	0x97, 0xCE, 0x70, 0x86, 0x74, 0xD5, 0x6A, 0xCD, 0xDC, 0x37, 0x10, 0x74, 0x40, 0x18, 0xD0, 0xB7,
	0x41, 0xE9, 0x99, 0xFE, 0x2B, 0xC4, 0x9E, 0x35, 0x91, 0x35, 0x1F, 0xCC, 0xC1, 0x0B, 0x83, 0x06,
	0x60, 0x41, 0x4E, 0xB9, 0x91, 0xEB, 0x2D, 0xF0, 0xA3, 0xA9, 0x85, 0x6A, 0xF8, 0x17, 0x75, 0x8A,
	0x11, 0x2F, 0x96, 0xB8, 0xF0, 0x5F, 0xEB, 0xBD, 0xE7, 0xA0, 0x39, 0xF7, 0x91, 0x68, 0xA3, 0xFF,
	0xE4, 0x17, 0x4B, 0x01, 0x67, 0x7E, 0xE5, 0xCF, 0xFC, 0x09, 0x18, 0xC2, 0xD2, 0x18, 0x84, 0x59,
	0x87, 0x91, 0x03, 0x89, 0x05, 0x9F, 0x01, 0x9C, 0xD5, 0xB6, 0xA7, 0xE8, 0xA2, 0xC5, 0xEC, 0x2C,
	0x04, 0x51, 0x3D, 0x2B, 0x38, 0xC7, 0xFE, 0x49, 0xBA, 0x41, 0xD8, 0x7E, 0xBF, 0x21, 0x2E, 0xF4,
	0x0E, 0x30, 0xFD, 0x73, 0xA4, 0xF7, 0x95, 0xF8, 0x5B, 0x74, 0x9A, 0xD6, 0x68, 0xC4, 0x0B, 0x9D,
	0x9F, 0x57, 0x5E, 0x6A, 0xC2, 0xDA, 0x1E, 0xBD, 0x5B, 0xB5, 0xD2, 0xA1, 0xC0, 0x0F, 0xD9, 0xA4,
	0x3E, 0xF8, 0xB4, 0xBE, 0x5E, 0x74, 0xBE, 0xBA, 0x06, 0x19, 0x4C, 0x2C, 0xD3, 0xE7, 0xBA, 0x68,
	0x43, 0x30, 0x78, 0x17, 0xBE, 0x95, 0x60, 0x23, 0xD3, 0x8D, 0x0F, 0x43, 0xE3, 0xAA, 0xE9, 0xC0,
	0x84, 0xD1, 0xDA, 0xB4, 0x99, 0x7E, 0x9E, 0xB9, 0xF4, 0x68, 0x21, 0x80, 0x01, 0x9B, 0x29, 0xC6,
	0x59, 0x58, 0xC8, 0x66, 0x24, 0xBD, 0x72, 0xF8, 0x3E, 0xB0, 0x9D, 0x41, 0x5A, 0x69, 0xD0, 0xF0,
	0xA6, 0xDA, 0x22, 0x79, 0xC4, 0x43, 0xD3, 0x61, 0xBC, 0x94, 0x8A, 0x49, 0xAD, 0x96, 0x6B, 0x07,
	0x29, 0x1F, 0xA1, 0xD5, 0x39, 0x82, 0xA5, 0x3D, 0x32, 0x4C, 0x48, 0xC6, 0x22, 0x29, 0x43, 0x3E,
	0xBB, 0x55, 0xD1, 0x21, 0x05, 0x7B, 0x84, 0xBB, 0x7B, 0x13, 0x5C, 0xE5, 0x02, 0x5B, 0x52, 0xCD,
	0xE3, 0x73, 0xD4, 0x67, 0xC2, 0xFD, 0x81, 0x25, 0xDC, 0xBC, 0x64, 0x5E, 0x98, 0xD0, 0xD3, 0xE0,
	0xCB, 0x53, 0x56, 0x7E, 0xD6, 0x08, 0x17, 0xD2, 0x16, 0x35, 0xBA, 0xBD, 0x52, 0x58, 0x94, 0x91,
	0x46, 0x8C, 0xC6, 0x8C, 0x90, 0x40, 0xA9, 0xED, 0x24, 0xF8, 0x8B, 0xE0, 0x33, 0xB0, 0x52, 0x3E,
	0x8B, 0xE9, 0xD2, 0xBC, 0xAD, 0x6A, 0x3E, 0x3D, 0x1A, 0xA2, 0xB6, 0xC0, 0x7F, 0x8E, 0xF8, 0xD3,
	0xD7, 0x8C, 0xC7, 0xA7, 0xCE, 0xE1, 0x75, 0x39, 0xE1, 0x79, 0x35, 0xC5, 0xCA, 0xFE, 0xD2, 0xB4,
	0x38, 0xE8, 0xA1, 0x95, 0x8A, 0xFB, 0xAA, 0xEE, 0xE8, 0xF5, 0x70, 0xCA, 0x29, 0x23, 0x7D, 0x8F,
	0x41, 0x3F, 0xE1, 0x7F, 0x59, 0xD3, 0x99, 0xF0, 0x65, 0x42, 0x74, 0x54, 0x50, 0xC4, 0x33, 0xD5,
	0x9C, 0x01, 0x84, 0xA5, 0xD8, 0xD9, 0xD3, 0x03, 0x8A, 0x8D, 0x28, 0x1B, 0x39, 0x6F, 0xD9, 0xB8,
	0x5A, 0x3D, 0xA0, 0x04, 0xE2, 0xD9, 0x63, 0x34, 0x3E, 0xE4, 0xCF, 0x40, 0x24, 0x74, 0x90, 0x0B,
	0xD8, 0x56, 0x4A, 0xC0, 0x1A, 0x68, 0x2C, 0xFB, 0xE3, 0x06, 0x21, 0xAA, 0xE5, 0x44, 0xD8, 0x37,
	0x42, 0xE9, 0x3F, 0x19, 0xBA, 0x39, 0xB6, 0x73, 0xF6, 0xDF, 0x34, 0xB8, 0x59, 0xBC, 0x89, 0x2F,
	0xBC, 0xEE, 0xB3, 0x0E, 0x6C, 0x36, 0x2C, 0x19, 0x2D, 0x99, 0x64, 0x2A, 0xC0, 0x00, 0x55, 0x09,
	0x03, 0xD8, 0x5D, 0xB0, 0x4F, 0x62, 0x0D, 0x0D, 0x70, 0x5F, 0x6F, 0xFE, 0x67, 0xDC, 0x32, 0xDA,
	0x44, 0xA0, 0xC7, 0x35
};

// contains the decryption block
const unsigned char DecryptionBlock[] = {
	0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81, 0x6F, 0xBA, 0xD9, 0xFA, 0x36, 0x16, 0x25, 0x01,
	0x8D, 0x04, 0x6E, 0x7E, 0xB4, 0x52, 0x7F, 0xA5, 0xBF, 0xA2, 0x92, 0xC1, 0xFF, 0x55, 0xA4, 0x4E,
	0x1D, 0xE6, 0x11, 0xFA, 0x60, 0xAC, 0x3D, 0xB3, 0xBE, 0x66, 0x44, 0xD6, 0x95, 0x3C, 0xAE, 0xAF,
	0xEF, 0xC4, 0xC6, 0xF8, 0x56, 0x5B, 0x78, 0x23, 0x82, 0xD1, 0xE2, 0x86, 0x39, 0x81, 0x0A, 0xC4,
	0xC6, 0xB9, 0xBB, 0x88, 0x15, 0x73, 0x1A, 0x2B, 0x04, 0x18, 0x77, 0xE7, 0xBA, 0x7F, 0x51, 0x36,
	0xB1, 0xB3, 0xAF, 0xF9, 0x2B, 0x6C, 0x4A, 0x05, 0x6D, 0xBD, 0xF1, 0xB1, 0xBD, 0x05, 0xD1, 0x2E,
	0x76, 0x7B, 0x69, 0xE3, 0x91, 0x02, 0xF7, 0x39, 0xBD, 0x3B, 0xFB, 0x67, 0xC8, 0xE1, 0xAF, 0x1A,
	0x3C, 0xCE, 0xA1, 0x8B, 0x7B, 0x16, 0x22, 0xF0, 0x6D, 0xC5, 0x67, 0xE6, 0x0F, 0xD5, 0x83, 0xD5,
	0x80, 0x44, 0xA6, 0xE5, 0xD5, 0x93, 0x5E, 0xA1, 0x2F, 0x92, 0xE8, 0xEB, 0x7F, 0xE5, 0xB0, 0x38
};

// decrypts a key (pilfered from ida)
BOOL sub_8ACC60(PBYTE pKey, PBYTE pData, PBYTE pBuff)
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

	v3 = *(_DWORD *)(a2 + 8);
	v4 = v3;
	v5 = *(_DWORD *)a2;
	v6 = *(_DWORD *)(a2 + 4);
	v7 = *(_DWORD *)(a2 + 12);
	v3 = __ROL4__(v3, 8);
	v4 = __ROR4__(v4, 8);
	v9 = v3 & 0xFF00FF | v4 & 0xFF00FF00;
	v10 = v7;
	v7 = __ROL4__(v7, 8);
	v10 = __ROR4__(v10, 8);
	v11 = v9;
	v12 = v9 ^ *(_DWORD *)(this + 0x8C);
	v125 = v7 & 0xFF00FF | v10 & 0xFF00FF00;
	v13 = v125 ^ v12 ^ *(_DWORD *)(this + 0x90);
	v14 = dword_AF8C00[(unsigned __int8)(v125 ^ v12 ^ *(_BYTE *)(this + 0x90))] ^ dword_AF9000[BYTE1(v13)] ^ dword_AF9400[(unsigned __int8)((v125 ^ v12 ^ *(_DWORD *)(this + 0x90)) >> 16)] ^ dword_AF9800[(v125 ^ v12 ^ *(_DWORD *)(this + 0x90)) >> 24];
	v15 = v14 + v12;
	v16 = dword_AF8C00[(unsigned __int8)v15] ^ dword_AF9000[BYTE1(v15)] ^ dword_AF9400[(unsigned __int8)(v15 >> 16)] ^ dword_AF9800[v15 >> 24];
	v17 = __ROR4__(v5, 8);
	v5 = __ROL4__(v5, 8);
	v18 = dword_AF8C00[(unsigned __int8)(v16 + v14)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v16 + v14) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v16 + v14) >> 16)] ^ dword_AF9800[(unsigned int)(v16 + v14) >> 24];
	v19 = (v18 + v16) ^ (v5 & 0xFF00FF | v17 & 0xFF00FF00);
	v20 = __ROR4__(v6, 8);
	v6 = __ROL4__(v6, 8);
	v21 = v18 ^ (v6 & 0xFF00FF | v20 & 0xFF00FF00);
	v22 = v19 ^ *(_DWORD *)(this + 0x84);
	v23 = dword_AF8C00[(unsigned __int8)(v21 ^ v22 ^ *(_BYTE *)(this + 0x88))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v21 ^ v22 ^ *(_WORD *)(this + 0x88)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v21 ^ v22 ^ *(_DWORD *)(this + 0x88)) >> 16)] ^ dword_AF9800[(v21 ^ v22 ^ *(_DWORD *)(this + 0x88)) >> 24];
	v24 = v23 + v22;
	v25 = dword_AF8C00[(unsigned __int8)v24] ^ dword_AF9000[BYTE1(v24)] ^ dword_AF9400[(unsigned __int8)(v24 >> 16)] ^ dword_AF9800[v24 >> 24];
	v26 = dword_AF8C00[(unsigned __int8)(v25 + v23)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v25 + v23) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v25 + v23) >> 16)] ^ dword_AF9800[(unsigned int)(v25 + v23) >> 24];
	v126 = v26 ^ v125;
	v27 = (v26 + v25) ^ v11;
	v28 = v27 ^ *(_DWORD *)(this + 0x7C);
	v29 = dword_AF8C00[(unsigned __int8)(v126 ^ v28 ^ *(_BYTE *)(this + 128))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v126 ^ v28 ^ *(_WORD *)(this + 128)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v126 ^ (unsigned int)v28 ^ *(_DWORD *)(this + 128)) >> 16)] ^ dword_AF9800[(v126 ^ (unsigned int)v28 ^ *(_DWORD *)(this + 128)) >> 24];
	v30 = v29 + v28;
	v31 = dword_AF8C00[(unsigned __int8)v30] ^ dword_AF9000[BYTE1(v30)] ^ dword_AF9400[(unsigned __int8)(v30 >> 16)] ^ dword_AF9800[v30 >> 24];
	v32 = dword_AF8C00[(unsigned __int8)(v31 + v29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v31 + v29) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v31 + v29) >> 16)] ^ dword_AF9800[(unsigned int)(v31 + v29) >> 24];
	v33 = v32 ^ v21;
	v34 = (v32 + v31) ^ v19;
	v35 = v34 ^ *(_DWORD *)(this + 116);
	v36 = dword_AF8C00[(unsigned __int8)(v33 ^ v35 ^ *(_BYTE *)(this + 120))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v33 ^ v35 ^ *(_WORD *)(this + 120)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v33 ^ (unsigned int)v35 ^ *(_DWORD *)(this + 120)) >> 16)] ^ dword_AF9800[(v33 ^ (unsigned int)v35 ^ *(_DWORD *)(this + 120)) >> 24];
	v37 = v36 + v35;
	v38 = dword_AF8C00[(unsigned __int8)v37] ^ dword_AF9000[BYTE1(v37)] ^ dword_AF9400[(unsigned __int8)(v37 >> 16)] ^ dword_AF9800[v37 >> 24];
	v39 = dword_AF8C00[(unsigned __int8)(v38 + v36)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v38 + v36) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v38 + v36) >> 16)] ^ dword_AF9800[(unsigned int)(v38 + v36) >> 24];
	v127 = v39 ^ v126;
	v40 = (v39 + v38) ^ v27;
	v41 = v40 ^ *(_DWORD *)(this + 108);
	v42 = dword_AF8C00[(unsigned __int8)(v127 ^ v41 ^ *(_BYTE *)(this + 112))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v127 ^ v41 ^ *(_WORD *)(this + 112)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v127 ^ (unsigned int)v41 ^ *(_DWORD *)(this + 112)) >> 16)] ^ dword_AF9800[(v127 ^ (unsigned int)v41 ^ *(_DWORD *)(this + 112)) >> 24];
	v43 = v42 + v41;
	v44 = dword_AF8C00[(unsigned __int8)v43] ^ dword_AF9000[BYTE1(v43)] ^ dword_AF9400[(unsigned __int8)(v43 >> 16)] ^ dword_AF9800[v43 >> 24];
	v45 = dword_AF8C00[(unsigned __int8)(v44 + v42)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v44 + v42) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v44 + v42) >> 16)] ^ dword_AF9800[(unsigned int)(v44 + v42) >> 24];
	v46 = v45 ^ v33;
	v47 = (v45 + v44) ^ v34;
	v48 = v47 ^ *(_DWORD *)(this + 100);
	v49 = dword_AF8C00[(unsigned __int8)(v46 ^ v48 ^ *(_BYTE *)(this + 104))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v46 ^ v48 ^ *(_WORD *)(this + 104)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v46 ^ (unsigned int)v48 ^ *(_DWORD *)(this + 104)) >> 16)] ^ dword_AF9800[(v46 ^ (unsigned int)v48 ^ *(_DWORD *)(this + 104)) >> 24];
	v50 = v49 + v48;
	v51 = dword_AF8C00[(unsigned __int8)v50] ^ dword_AF9000[BYTE1(v50)] ^ dword_AF9400[(unsigned __int8)(v50 >> 16)] ^ dword_AF9800[v50 >> 24];
	v52 = dword_AF8C00[(unsigned __int8)(v51 + v49)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v51 + v49) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v51 + v49) >> 16)] ^ dword_AF9800[(unsigned int)(v51 + v49) >> 24];
	v128 = v52 ^ v127;
	v53 = (v52 + v51) ^ v40;
	v54 = v53 ^ *(_DWORD *)(this + 92);
	v55 = dword_AF8C00[(unsigned __int8)(v128 ^ v54 ^ *(_BYTE *)(this + 96))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v128 ^ v54 ^ *(_WORD *)(this + 96)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v128 ^ (unsigned int)v54 ^ *(_DWORD *)(this + 96)) >> 16)] ^ dword_AF9800[(v128 ^ (unsigned int)v54 ^ *(_DWORD *)(this + 96)) >> 24];
	v56 = v55 + v54;
	v57 = dword_AF8C00[(unsigned __int8)v56] ^ dword_AF9000[BYTE1(v56)] ^ dword_AF9400[(unsigned __int8)(v56 >> 16)] ^ dword_AF9800[v56 >> 24];
	v58 = dword_AF8C00[(unsigned __int8)(v57 + v55)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v57 + v55) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v57 + v55) >> 16)] ^ dword_AF9800[(unsigned int)(v57 + v55) >> 24];
	v59 = (v58 + v57) ^ v47;
	v60 = v58 ^ v46;
	v61 = v59 ^ *(_DWORD *)(this + 84);
	v62 = dword_AF8C00[(unsigned __int8)(v60 ^ v61 ^ *(_BYTE *)(this + 88))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v60 ^ v61 ^ *(_WORD *)(this + 88)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v60 ^ (unsigned int)v61 ^ *(_DWORD *)(this + 88)) >> 16)] ^ dword_AF9800[(v60 ^ (unsigned int)v61 ^ *(_DWORD *)(this + 88)) >> 24];
	v63 = v62 + v61;
	v64 = dword_AF8C00[(unsigned __int8)v63] ^ dword_AF9000[BYTE1(v63)] ^ dword_AF9400[(unsigned __int8)(v63 >> 16)] ^ dword_AF9800[v63 >> 24];
	v65 = dword_AF8C00[(unsigned __int8)(v64 + v62)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v64 + v62) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v64 + v62) >> 16)] ^ dword_AF9800[(unsigned int)(v64 + v62) >> 24];
	v129 = v65 ^ v128;
	v66 = (v65 + v64) ^ v53;
	v67 = v66 ^ *(_DWORD *)(this + 76);
	v68 = dword_AF8C00[(unsigned __int8)(v129 ^ v67 ^ *(_BYTE *)(this + 80))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v129 ^ v67 ^ *(_WORD *)(this + 80)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v129 ^ (unsigned int)v67 ^ *(_DWORD *)(this + 80)) >> 16)] ^ dword_AF9800[(v129 ^ (unsigned int)v67 ^ *(_DWORD *)(this + 80)) >> 24];
	v69 = v68 + v67;
	v70 = dword_AF8C00[(unsigned __int8)v69] ^ dword_AF9000[BYTE1(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];
	v71 = dword_AF8C00[(unsigned __int8)(v70 + v68)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v70 + v68) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v70 + v68) >> 16)] ^ dword_AF9800[(unsigned int)(v70 + v68) >> 24];
	v72 = v71 ^ v60;
	v73 = (v71 + v70) ^ v59;
	v74 = v73 ^ *(_DWORD *)(this + 68);
	v75 = dword_AF8C00[(unsigned __int8)(v72 ^ v74 ^ *(_BYTE *)(this + 72))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v72 ^ v74 ^ *(_WORD *)(this + 72)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v72 ^ (unsigned int)v74 ^ *(_DWORD *)(this + 72)) >> 16)] ^ dword_AF9800[(v72 ^ (unsigned int)v74 ^ *(_DWORD *)(this + 72)) >> 24];
	v76 = v75 + v74;
	v77 = dword_AF8C00[(unsigned __int8)v76] ^ dword_AF9000[BYTE1(v76)] ^ dword_AF9400[(unsigned __int8)(v76 >> 16)] ^ dword_AF9800[v76 >> 24];
	v78 = dword_AF8C00[(unsigned __int8)(v77 + v75)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v77 + v75) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v77 + v75) >> 16)] ^ dword_AF9800[(unsigned int)(v77 + v75) >> 24];
	v130 = v78 ^ v129;
	v79 = (v78 + v77) ^ v66;
	v80 = v79 ^ *(_DWORD *)(this + 60);
	v81 = dword_AF8C00[(unsigned __int8)(v130 ^ v80 ^ *(_BYTE *)(this + 64))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v130 ^ v80 ^ *(_WORD *)(this + 64)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v130 ^ (unsigned int)v80 ^ *(_DWORD *)(this + 64)) >> 16)] ^ dword_AF9800[(v130 ^ (unsigned int)v80 ^ *(_DWORD *)(this + 64)) >> 24];
	v82 = v81 + v80;
	v83 = dword_AF8C00[(unsigned __int8)v82] ^ dword_AF9000[BYTE1(v82)] ^ dword_AF9400[(unsigned __int8)(v82 >> 16)] ^ dword_AF9800[v82 >> 24];
	v84 = dword_AF8C00[(unsigned __int8)(v83 + v81)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v83 + v81) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v83 + v81) >> 16)] ^ dword_AF9800[(unsigned int)(v83 + v81) >> 24];
	v85 = v84 ^ v72;
	v86 = (v84 + v83) ^ v73;
	v87 = v86 ^ *(_DWORD *)(this + 52);
	v88 = dword_AF8C00[(unsigned __int8)(v85 ^ v87 ^ *(_BYTE *)(this + 56))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v85 ^ v87 ^ *(_WORD *)(this + 56)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v85 ^ (unsigned int)v87 ^ *(_DWORD *)(this + 56)) >> 16)] ^ dword_AF9800[(v85 ^ (unsigned int)v87 ^ *(_DWORD *)(this + 56)) >> 24];
	v89 = v88 + v87;
	v90 = dword_AF8C00[(unsigned __int8)v89] ^ dword_AF9000[BYTE1(v89)] ^ dword_AF9400[(unsigned __int8)(v89 >> 16)] ^ dword_AF9800[v89 >> 24];
	v91 = dword_AF8C00[(unsigned __int8)(v90 + v88)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v90 + v88) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v90 + v88) >> 16)] ^ dword_AF9800[(unsigned int)(v90 + v88) >> 24];
	v131 = v91 ^ v130;
	v92 = (v91 + v90) ^ v79;
	v93 = v92 ^ *(_DWORD *)(this + 44);
	v94 = dword_AF8C00[(unsigned __int8)(v131 ^ v93 ^ *(_BYTE *)(this + 48))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v131 ^ v93 ^ *(_WORD *)(this + 48)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v131 ^ (unsigned int)v93 ^ *(_DWORD *)(this + 48)) >> 16)] ^ dword_AF9800[(v131 ^ (unsigned int)v93 ^ *(_DWORD *)(this + 48)) >> 24];
	v95 = v94 + v93;
	v96 = dword_AF8C00[(unsigned __int8)v95] ^ dword_AF9000[BYTE1(v95)] ^ dword_AF9400[(unsigned __int8)(v95 >> 16)] ^ dword_AF9800[v95 >> 24];
	v97 = dword_AF8C00[(unsigned __int8)(v96 + v94)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v96 + v94) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v96 + v94) >> 16)] ^ dword_AF9800[(unsigned int)(v96 + v94) >> 24];
	v98 = v97 ^ v85;
	v99 = (v97 + v96) ^ v86;
	v100 = v99 ^ *(_DWORD *)(this + 36);
	v101 = dword_AF8C00[(unsigned __int8)(v98 ^ v100 ^ *(_BYTE *)(this + 40))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v98 ^ v100 ^ *(_WORD *)(this + 40)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v98 ^ (unsigned int)v100 ^ *(_DWORD *)(this + 40)) >> 16)] ^ dword_AF9800[(v98 ^ (unsigned int)v100 ^ *(_DWORD *)(this + 40)) >> 24];
	v102 = v101 + v100;
	v103 = dword_AF8C00[(unsigned __int8)v102] ^ dword_AF9000[BYTE1(v102)] ^ dword_AF9400[(unsigned __int8)(v102 >> 16)] ^ dword_AF9800[v102 >> 24];
	v104 = dword_AF8C00[(unsigned __int8)(v103 + v101)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v103 + v101) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v103 + v101) >> 16)] ^ dword_AF9800[(unsigned int)(v103 + v101) >> 24];
	v132 = v104 ^ v131;
	v105 = (v104 + v103) ^ v92;
	v106 = v105 ^ *(_DWORD *)(this + 28);
	v107 = dword_AF8C00[(unsigned __int8)(v132 ^ v106 ^ *(_BYTE *)(this + 32))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v132 ^ v106 ^ *(_WORD *)(this + 32)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v132 ^ (unsigned int)v106 ^ *(_DWORD *)(this + 32)) >> 16)] ^ dword_AF9800[(v132 ^ (unsigned int)v106 ^ *(_DWORD *)(this + 32)) >> 24];
	v108 = v107 + v106;
	v109 = dword_AF8C00[(unsigned __int8)v108] ^ dword_AF9000[BYTE1(v108)] ^ dword_AF9400[(unsigned __int8)(v108 >> 16)] ^ dword_AF9800[v108 >> 24];
	v110 = dword_AF8C00[(unsigned __int8)(v109 + v107)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v109 + v107) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v109 + v107) >> 16)] ^ dword_AF9800[(unsigned int)(v109 + v107) >> 24];
	v111 = v110 ^ v98;
	v112 = (v110 + v109) ^ v99;
	v113 = v112 ^ *(_DWORD *)(this + 20);
	v114 = dword_AF8C00[(unsigned __int8)(v111 ^ v113 ^ *(_BYTE *)(this + 24))] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v111 ^ v113 ^ *(_WORD *)(this + 24)) >> 8)] ^ dword_AF9400[(unsigned __int8)((v111 ^ (unsigned int)v113 ^ *(_DWORD *)(this + 24)) >> 16)] ^ dword_AF9800[(v111 ^ (unsigned int)v113 ^ *(_DWORD *)(this + 24)) >> 24];
	v115 = v114 + v113;
	v116 = dword_AF8C00[(unsigned __int8)v115] ^ dword_AF9000[BYTE1(v115)] ^ dword_AF9400[(unsigned __int8)(v115 >> 16)] ^ dword_AF9800[v115 >> 24];
	v117 = dword_AF8C00[(unsigned __int8)(v116 + v114)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v116 + v114) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v116 + v114) >> 16)] ^ dword_AF9800[(unsigned int)(v116 + v114) >> 24];
	v118 = (v117 + v116) ^ v105;
	v119 = v118;
	v118 = __ROL4__(v118, 8);
	v119 = __ROR4__(v119, 8);
	*(_DWORD *)a3 = v118 & 0xFF00FF | v119 & 0xFF00FF00;
	v120 = __ROR4__(v117 ^ v132, 8);
	v121 = __ROL4__(v117 ^ v132, 8);
	*(_DWORD *)(a3 + 4) = v121 & 0xFF00FF | v120 & 0xFF00FF00;
	v122 = __ROR4__(v112, 8);
	v112 = __ROL4__(v112, 8);
	*(_DWORD *)(a3 + 8) = v112 & 0xFF00FF | v122 & 0xFF00FF00;
	v123 = v111;
	v111 = __ROL4__(v111, 8);
	v123 = __ROR4__(v123, 8);
	result = v111 & 0xFF00FF | v123 & 0xFF00FF00;
	*(_DWORD *)(a3 + 0xC) = result;
	return result;
}

// the program entry point
int main()
{
	// creates a new cryptor object
	CryptorSeedCBC Cryptor;
	cin.get();
	// stores the cryptor seed
	PBYTE pSeed = new BYTE[16]{ 0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89 };
	// stores the cryptor key
	PBYTE pKey = new BYTE[16]{ 0x26, 0x8D, 0x66, 0xA7, 0x35, 0xA8, 0x1A, 0x81, 0x6F, 0xBA, 0xD9, 0xFA, 0x36, 0x16, 0x25, 0x01 };
	// initalizes the cryptor
	if (Cryptor.init((PDWORD)pSeed, (PDWORD)pKey))
	{
		// notifes the user
		cout << "Done." << endl;
		cout << *(DWORD*)YourMum << endl;
		cout << Cryptor.decrypt(&YourMum[4], sizeof(YourMum) - 4) << endl;
	}
	cin.get();
	return 0;
}