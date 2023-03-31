#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "msdirent.h"
#include "openssl/evp.h"
#include "openssl/ec.h"



//�t�@�C���̃T�C�Y���v������֐�
unsigned long GetFileSize(const char* fname) {
	long size;
	FILE* fgetfilesize;

	fgetfilesize = fopen(fname, "rb");
	if (fgetfilesize == NULL) {
		printf("%s�t�@�C�����J���܂���\n", fname);
		return -1;
	}

	fseek(fgetfilesize, 0, SEEK_END);
	size = ftell(fgetfilesize);
	fclose(fgetfilesize);
	return(size);
}




//AES�����ۂɍs���֐�
int AES(const char* in_fname, const char* out_fname, unsigned char* key, unsigned char* iv, int do_encrypt) {
	//do_encrypt==1 �Í��� 
	//do_encrypt==0 ����

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

	//�o�b�t�@�T�C�Y�̐ݒ�

	in_size = GetFileSize(in_fname);
	printf("size=%lu\n", in_size);

	inbuf = (unsigned char*)malloc(sizeof(char) * in_size);
	if (inbuf == NULL) {
		printf("���������m�ۂł��܂���\n");
		//		exit(EXIT_FAILURE);
	}
	outbuf = (unsigned char*)malloc(sizeof(char) * (int)(in_size + EVP_MAX_BLOCK_LENGTH));

	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);
	//AES128�̌��Ə����x�N�g����ݒ�
	EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);
	for (;;) {
		inlen = fread(inbuf, 1, in_size, fin);
		//fread�ɂ���
		//1.�o�b�t�@inbuf��
		//2.�T�C�Y1�̃f�[�^
		//3.in_size��
		//4.�t�@�C���|�C���^fin����ǂݍ���
		//�ǂݎ��������Ԃ�
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
		strcpy(original, infolda);//�I���W�i���̃t�@�C��������
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//�����t�@�C��������
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
		strcpy(original, infolda);//�I���W�i���̃t�@�C��������
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//�����t�@�C��������
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

	printf("�Í��� ���s���܂�\n");
	printf("���̓���\n");
	scanf("%s", key);


	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//�I���W�i���̃t�@�C��������
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//�����t�@�C��������
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

	printf("���� ���s���܂�\n");
	printf("���̓���\n");
	scanf("%s", key);


	for (dp = readdir(dir); dp != NULL; dp = readdir(dir)) {
		strcpy(original, infolda);//�I���W�i���̃t�@�C��������
		strcat(original, "/");
		strcat(original, dp->d_name);
		strcpy(operated, outfolda);//�����t�@�C��������
		strcat(operated, "/");
		strcat(operated, dp->d_name);
		printf("%s, %s\n", original, operated);
		if (*dp->d_name != '.')
			AES(original, operated, key, iv, 0);

	}

	closedir(dir);
}





//����
int main(void) {
	char infolda[] = "enc";//�����������t�@�C���̓����Ă���t�H���_
	char outfolda[] = "dec";//���������t�@�C���̍s����
	unsigned char iv[] = "0123456789abcdef";

	AES_dec_folda_inputkey(infolda, outfolda, iv);

	return 0;
}



/*
//�Í���
int main(void) {
	char infolda[] = "plain";//�����������t�@�C���̓����Ă���t�H���_
	char outfolda[] = "enc";//���������t�@�C���̍s����
	unsigned char iv[] = "0123456789abcdef";

	AES_enc_folda_inputkey(infolda, outfolda, iv);

	return 0;
}
*/



