#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "msdirent.h"
#include "openssl/evp.h"
#include "openssl/ec.h"



//ファイルのサイズを計測する関数
unsigned long GetFileSize(const char* fname) {
	long size;
	FILE* fgetfilesize;

	fgetfilesize = fopen(fname, "rb");
	if (fgetfilesize == NULL) {
		printf("%sファイルが開けません\n", fname);
		return -1;
	}

	fseek(fgetfilesize, 0, SEEK_END);
	size = ftell(fgetfilesize);
	fclose(fgetfilesize);
	return(size);
}




//AESを実際に行う関数
int AES(const char* in_fname, const char* out_fname, unsigned char* key, unsigned char* iv, int do_encrypt) {
	//do_encrypt==1 暗号化 
	//do_encrypt==0 復号

	//Allow enough space in output buffer for additional block

//	unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char* inbuf, * outbuf;

	int inlen, outlen;
	//EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	// Bogus key and IV: we'd normally set these from
	// another source.
	//

	FILE* fin, * fout;
	unsigned long in_size;

	fin = fopen(in_fname, "rb");
	fout = fopen(out_fname, "wb");

	//バッファサイズの設定

	in_size = GetFileSize(in_fname);
	printf("size=%lu\n", in_size);

	inbuf = (unsigned char*)malloc(sizeof(char) * in_size);
	if (inbuf == NULL) {
		printf("メモリが確保できません\n");
		//		exit(EXIT_FAILURE);
	}
	outbuf = (unsigned char*)malloc(sizeof(char) * (int)(in_size + EVP_MAX_BLOCK_LENGTH));

	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
	//AES128の鍵と初期ベクトルを設定
	EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);
	for (;;) {
		inlen = fread(inbuf, 1, in_size, fin);
		//freadについて
		//1.バッファinbufに
		//2.サイズ1のデータ
		//3.in_size個を
		//4.ファイルポインタfinから読み込み
		//読み取った個数を返す
		if (inlen <= 0) break;
		if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
			// Error 
			//EVP_CIPHER_CTX_cleanup(ctx);
			EVP_CIPHER_CTX_free(ctx);
			fclose(fin);
			fclose(fout);
			free(inbuf);
			free(outbuf);
			return 0;
		}
		fwrite(outbuf, 1, outlen, fout);
	}
	if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen)) {
		// Error 
		//EVP_CIPHER_CTX_cleanup(ctx);
		EVP_CIPHER_CTX_free(ctx);
		fclose(fin);
		fclose(fout);
		free(inbuf);
		free(outbuf);
		return 0;
	}
	fwrite(outbuf, 1, outlen, fout);
	//EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);
	fclose(fin);
	fclose(fout);
	free(inbuf);
	free(outbuf);
	return 1;
}










void AES_enc_folda(char* infolda, char* outfolda, unsigned char* key, unsigned char* iv) {
	DIR* dir;
	struct dirent* dp;
	char original[100];
	char operated[100];
	dir = opendir(infolda);

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//オリジナルのファイル名生成
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//処理ファイル名生成
		strcat(operated, "/");
		strcat(operated, dp->d_name);
		printf("%s, %s\n", original, operated);
		if (*dp->d_name != '.')
			AES(original, operated, key, iv, 1);

	}

	closedir(dir);
}

void AES_dec_folda(char* infolda, char* outfolda, unsigned char* key, unsigned char* iv) {
	DIR* dir;
	struct dirent* dp;
	char original[100];
	char operated[100];
	dir = opendir(infolda);

	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//オリジナルのファイル名生成
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//処理ファイル名生成
		strcat(operated, "/");
		strcat(operated, dp->d_name);
		printf("%s, %s\n", original, operated);
		if (*dp->d_name != '.')
			AES(original, operated, key, iv, 0);

	}

	closedir(dir);
}



void AES_enc_folda_inputkey(char* infolda, char* outfolda, unsigned char* iv) {
	DIR* dir;
	struct dirent* dp;
	char original[100];
	char operated[100];
	dir = opendir(infolda);
	unsigned char key[128];

	printf("暗号化 を行います\n");
	printf("鍵の入力\n");
	scanf("%s", key);


	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//オリジナルのファイル名生成
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//処理ファイル名生成
		strcat(operated, "/");
		strcat(operated, dp->d_name);
		printf("%s, %s\n", original, operated);
		if (*dp->d_name != '.')
			AES(original, operated, key, iv, 1);

	}

	closedir(dir);
}


void AES_dec_folda_inputkey(char* infolda, char* outfolda, unsigned char* iv) {
	DIR* dir;
	struct dirent* dp;
	char original[100];
	char operated[100];
	dir = opendir(infolda);
	unsigned char key[128];

	printf("復号 を行います\n");
	printf("鍵の入力\n");
	scanf("%s", key);


	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//オリジナルのファイル名生成
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//処理ファイル名生成
		strcat(operated, "/");
		strcat(operated, dp->d_name);
		printf("%s, %s\n", original, operated);
		if (*dp->d_name != '.')
			AES(original, operated, key, iv, 0);

	}

	closedir(dir);
}





//復号
int main(void) {
	char infolda[] = "enc";//処理したいファイルの入っているフォルダ
	char outfolda[] = "dec";//処理したファイルの行き先
	unsigned char iv[] = "0123456789abcdef";

	AES_dec_folda_inputkey(infolda, outfolda, iv);

	return 0;
}



/*
//暗号化
int main(void) {
	char infolda[] = "plain";//処理したいファイルの入っているフォルダ
	char outfolda[] = "enc";//処理したファイルの行き先
	unsigned char iv[] = "0123456789abcdef";

	AES_enc_folda_inputkey(infolda, outfolda, iv);

	return 0;
}
*/



