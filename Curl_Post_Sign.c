
#include <openssl/sha.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/evp.h>
#include <openssl/pem.h>

const char curlpost_tmplt[] = "curl -X POST https://warm-ridge.herokuapp.com/api/verify -H 'accept: application/json' -H 'content-type: application/json' -d '{\"message\": \"%s\", \"signature\": \"%s\"}'";

const char RespFile[] = "/tmp/response";

unsigned char sha256_hash[SHA256_DIGEST_LENGTH]; // 32 bytes
const char message[] = "hello iot";
char messageTmp[] = "hello iot";
#define BASE64_BUF_SIZE 256
static char base64Sign[BASE64_BUF_SIZE] = "MEUCIGNWkxSoIt5Z1QenH5agnhBZa1txcPZU5p+QBTR6MrJaAiEAzb+mOLxb80TQ/vVnvqddnlEDb3JjkzlDNy6eoD7kBGo=";
unsigned int base64_Signlen=0;

ECDSA_SIG *dsa_sig;
unsigned char	*dersignature = NULL;
unsigned int	sig_len;

EC_KEY *eckey;

bool Check_CurlResponse();
int hash_sign_encode();

static bool find_SHA256(char* input, unsigned long length, unsigned char* md)
{
	SHA256_CTX context;
	if(!SHA256_Init(&context))
		return false;

	if(!SHA256_Update(&context, (char*)input, length))
		return false;

	if(!SHA256_Final(md, &context))
		return false;

	return true;
}

static bool create_ec_keys(unsigned char* hash)
{
	BIGNUM start;
	BIGNUM *res; 
	BIGNUM *bnprivkey, *bnpubkey;
	BN_CTX *ctx;

	EC_POINT *pubkeypoint = NULL;
	const EC_GROUP *group = NULL;

	BN_init(&start);

	ctx = BN_CTX_new();
 
	bnprivkey = &start;

	// base64 decoded and hexdump of EF+NgtFsjaZjGsQVsLB6n4xndh7mP0ye44r4SWFLKCM=
	BN_hex2bn(&bnprivkey, "105f8d82d16c8da6631ac415b0b07a9f8c67761ee63f4c9ee38af849614b2823");

	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

	group = EC_KEY_get0_group(eckey);
	pubkeypoint = EC_POINT_new(group); 

	if (!EC_KEY_set_private_key(eckey, bnprivkey))
	{
		printf("Error in EC_KEY_set_private_key \n");
		return false;
	}

	bnpubkey = BN_new();

	if(EC_POINT_mul(group, pubkeypoint, bnprivkey, NULL, NULL, ctx) != 1)
	{
		printf("Error in EC_POINT_mul \n");
		return false;
	}
	//------------------------
	unsigned char *pubkey;
	bnpubkey = EC_POINT_point2bn(group, pubkeypoint, POINT_CONVERSION_UNCOMPRESSED, bnpubkey, ctx);

	pubkey = (unsigned char *)malloc(sizeof(unsigned char) * (BN_num_bytes(bnpubkey) + 1));
	BN_bn2bin(bnpubkey, pubkey);

	//  printf(" PUB Key: %s \n Len = %d\n", pubkey, BN_num_bytes(bnpubkey));

	if(EC_KEY_set_public_key(eckey, pubkeypoint) != 1)
	{
		printf("ERROR: Can't set public key!\r\n");
		return false;
	}

	if (!EC_KEY_check_key(eckey)) {
		printf("ERROR: EC_KEY_check_key failed:\n");
		//printf("%s\n",ERR_error_string(ERR_get_error(),NULL));
		return false;
	} else {
		printf("EC key check OK\n");
	} 

	return true;
}

static bool Sign_the_hash(unsigned char *hash)
{
	//printf("************ ECDSA_size sig_len = %d\n", sig_len);

	dersignature = OPENSSL_malloc(sig_len);
	if(dersignature == NULL)
	{
		printf("OPENSSL_malloc error\n");
		return false;
	}

	if(!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, dersignature, &sig_len, eckey))
	{
		printf("ECDSA_sign failed\n");
		return false;
	}

	if(ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, dersignature, sig_len, eckey) != 1)
	{
		printf(" failed (verify), ECDSA_verify\n");
		return false;
	}

	//printf("DER Signature char: strlen = %d, %s\n", strlen(dersignature), dersignature);

	printf("\nDER Signature:   ");
	for (unsigned int n = 0; n < sig_len; ++n) {
			printf("%02x", dersignature[n]);
	}
	printf(" , len = %d\n", sig_len);

	return true;
}


static unsigned int signBase64_SignatureDSA(char * base64SignatureBuf, unsigned int base64SignatureBufLen)
{
	BIO * b64 = BIO_new(BIO_f_base64());
	BIO * bmem = BIO_new(BIO_s_mem());
	unsigned int sigValLen = 0;

	BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
	BIO_set_flags(bmem,BIO_FLAGS_BASE64_NO_NL);

	b64 = BIO_push(b64, bmem);

	// Convert signature to Base64
	BIO_write(b64, dersignature, sig_len);
	BIO_flush(b64);

	//printf("\nRaw Signature: %s\n", dersignature);

	sigValLen = BIO_read(bmem, base64SignatureBuf, base64SignatureBufLen);

	//printf("base64 SignatureVal Len: %d \n", sigValLen);

	BIO_free_all(b64);

	OPENSSL_free(dersignature);

	if (sigValLen <= 0) {
		printf("OpenSSL:EC - Error converting signature to raw buffer\n");
		return false;
	}

	return sigValLen;
}


static int Curl_Loop()
{
	bool CurlRet =0;
	int len = strlen(message);
	int i=0, pos = 0;
	char *post_string = NULL;

	while(1)
	{
		// Message Shift copy
		strcpy(messageTmp, message + pos);

		//========= Left Shift the Message =================//
		if(pos > 0)
		{
			strncpy(messageTmp + (len - pos), message, pos);
		}

		printf("\n\n ----------- Next Message ------------ \n");
		printf("Message: %s\n", messageTmp);

		if(pos !=0 )
			pos--;
		else
			pos = len-1;

		//======== do Hash, Sign and base64 encoding ========//
		if(hash_sign_encode() != true)
		{
			return false;
		}

		post_string = malloc(strlen(curlpost_tmplt) + base64_Signlen + strlen(message) + strlen(RespFile) + 4);

		// Construct the CURL post command
		sprintf(post_string, curlpost_tmplt, messageTmp, base64Sign);

		strcat(post_string," > ");
		strcat(post_string, RespFile);

		printf("Curl Command:\n %s\n", post_string);

		// execute the curl post using system command
		system(post_string);
		printf("\n");

		// check the check response is success or fail
		CurlRet = Check_CurlResponse();
//#if 0
		//If the response is Failure, break the loop
		if(CurlRet == false)
		{
			free(post_string);
			break;
		}
//#endif

		free(post_string);

		sleep(10);
	 }
}


bool Check_CurlResponse()
{
	FILE *fp;
	char *ret = NULL;
	const char Success_Resp[] = "signature_matched_with_message";

	fp = fopen(RespFile, "r");

	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	char *string = malloc(fsize + 1);
	fread(string, fsize, 1, fp);

	fclose(fp);

	printf("CurlResponse: fread: %s, fsize = %d\n", string, fsize);

	// Compare the response with the success string
	ret = strstr(string, Success_Resp);

	free(string);

	if(ret!= NULL)
	{
		printf("CURL POST Response Success\n");
		return true;
	}
	else
	{
		printf("CURL POST Response Failure\n");
		return false;
	}

}


int hash_sign_encode()
{
	int status, i;

	// =============== Find HASH =================//
	if(!find_SHA256(messageTmp, strlen(messageTmp), sha256_hash))
	{
		printf("SHA256 Error \n");
		return false;
	}

	printf("SHA256:	");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		printf("%02x ", sha256_hash[i]);
	}
	printf("\n");

	//=============== SIGN the HASH =================//
	if(Sign_the_hash(sha256_hash) != true)
	{
		return false;
	}

	//=============== Base 64 encode the Signature =============//
	base64_Signlen = signBase64_SignatureDSA(&base64Sign[0], BASE64_BUF_SIZE);
	printf("\nBase64 Signature: %s  , base64_Signlen = %d \n\n", base64Sign, base64_Signlen);
	if(base64_Signlen == false)
	{
		return false;
	}

	return true;
}

int main()
{
	int i;

	printf("Start Main \n");
	int status = create_ec_keys(sha256_hash);
 
	// get the DER signature length and update
	sig_len = ECDSA_size(eckey);
	printf("DER Sign Length = %d\n", sig_len);

	// =========== Debug: Print the keys ==============//
	printf("\n\n\n");
	BIO *out,*outfile;
	out=BIO_new(BIO_s_file()); // for commandline output
	BIO_set_fp(out,stdout,BIO_NOCLOSE);
	outfile = BIO_new(BIO_s_file());
	if (!EC_KEY_print(out, eckey, 0))
	{	perror("EC_KEY_print ");
	}
	PEM_write_bio_EC_PUBKEY(out, eckey);
	printf("\n\n\n");

	//============ main loop ==================//
	Curl_Loop();

	printf("End Main \n");
}
