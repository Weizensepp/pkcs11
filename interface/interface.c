/* A PKCS#11 API for HSMs
*
* Author: Ferdinand Pohl
*
*/

/* Inlcudes */

#include "pkcs11.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>


/*Makros*/
#define MAX_PWD_LEN  200
#define MAX_LABEL_LEN  200
#define MAX_SLOTS 20


/* Global variables */

char cryptoki_lib_dest[4096] = {0};
CK_FUNCTION_LIST_PTR p11_functions = NULL_PTR;
CK_VOID_PTR lib_handle = NULL_PTR;
CK_BBOOL istrue = CK_TRUE;


void logger(int rv, char *msg, int line, const char* file, const char *func)
{
	printf("\n0x%x : %s : %s : %s : %d \n",rv,msg,func,file,line);
}

CK_RV get_library()
{
	CK_RV rv = CKR_OK;
	char *lib_path = NULL;
	char *lib_name = NULL;

	lib_path = getenv("CRYPTOKI_LIB_PATH");
	if( lib_path == NULL )
	{
		printf("Failed to get CRYPTOKI_LIB_PATH");
		rv = CKR_GENERAL_ERROR;
		goto exit;
	}

	lib_name = getenv("CRYPTOKI_LIB_NAME");
	if (lib_name == NULL)
	{
		rv = CKR_GENERAL_ERROR;
		logger(rv,"Failed to get CRYPTOKI_LIB_NAME",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	snprintf(cryptoki_lib_dest,sizeof(cryptoki_lib_dest)-1,"%s/%s",lib_path,lib_name);

	printf("\nCryptoki will load the library: %s \n",cryptoki_lib_dest);

	exit:
		return rv;
}

CK_RV load_pkcs11_funtions(){
	CK_RV rv = CKR_OK;
	CK_C_GetFunctionList p11_function_list;

	rv = get_library();
	
	if ( rv != CKR_OK){
		logger(rv,"get_libary() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	lib_handle = dlopen(cryptoki_lib_dest,RTLD_NOW);

	if(lib_handle == NULL){
		rv= CKR_GENERAL_ERROR;
		logger(rv,"dlopen() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	p11_function_list = (CK_C_GetFunctionList) dlsym(lib_handle, "C_GetFunctionList");

 	rv = p11_function_list(&p11_functions);
	
	if ( rv != CKR_OK ){
		logger(rv,"function_symbol_list() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	if(p11_functions)
	{
		rv = p11_functions->C_Initialize(NULL_PTR);
		if( rv != CKR_OK )
		{
			logger(rv,"C_Initialize() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}
	}
	printf("Functions loaded succesfully\n");
	exit:
		return rv;
}


CK_RV get_slot_num(){
	
	CK_RV rv = CKR_OK;
	CK_ULONG ulSlot_count = 0;
//	CK_BBOOL token_present = CK_TRUE;
	CK_SLOT_ID_PTR pSlot_List;
	
	rv = p11_functions -> C_GetSlotList(CK_FALSE,NULL_PTR,&ulSlot_count);
	if( rv != CKR_OK )
	{
		logger(rv,"C_GetSlotList() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	if(rv == CKR_OK){
		pSlot_List = (CK_SLOT_ID_PTR) malloc(ulSlot_count*sizeof(CK_SLOT_ID));
		rv = p11_functions->C_GetSlotList(CK_FALSE, pSlot_List, &ulSlot_count);
		if(rv == CKR_OK){
			printf("\nAvailable Slots: %ld \n",ulSlot_count);
		}
		free(pSlot_List);
	}
	
	exit:
		return rv;

}

CK_RV open_session(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession){

	CK_RV rv = CKR_OK;
	CK_BYTE application = 1;

	rv = p11_functions -> C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION,&application, CK_FALSE, &hSession);
	if(rv != CKR_OK){
		logger(rv, "C_OpenSession() failed", __LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	exit:
		return rv;
}


CK_RV initilaize_token(CK_SLOT_ID slotID){
	
	CK_RV rv = CKR_OK;
	CK_UTF8CHAR pin[] = {"123456"};
	CK_UTF8CHAR label[32];

	//memset(&label, " ", sizeof(label));
	memcpy(&label, "Token1", strlen("Token1"));

	rv = p11_functions->C_InitToken(slotID,pin,sizeof(pin)-1,label);
	if(rv != CKR_OK){
		logger(rv,"C_InitToken() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	if(rv == CKR_OK){
	printf("\nToken initialized succesfully \n");
	}
	exit:
		return rv;
}

CK_RV init_pin(CK_SLOT_ID slotID){

	CK_BYTE application;
	CK_SESSION_HANDLE hSession;
	CK_UTF8CHAR newPin[]= {"123456"};
	CK_UTF8CHAR soPin[] = {"123456"};
	CK_RV rv = CKR_OK;

	application = 1;

	rv = p11_functions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, &application, FALSE, &hSession);
	if(rv != CKR_OK){
		logger(rv,"C_OpenSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_Login(hSession,CKU_SO,soPin,sizeof(soPin)-1);
	if(rv != CKR_OK){
		logger(rv,"C_Login() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions-> C_InitPIN(hSession, newPin, sizeof(newPin)-1);
	if(rv != CKR_OK){
		logger(rv,"C_InitPIN() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_Logout(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_Logout() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_CloseSession(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_CloseSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	printf("Pin initialized succesfully!");
	exit:
		return rv;
}


CK_RV generate_key_pair_rsa(CK_SLOT_ID slotID){
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CK_CHAR label[] = {"rsa"};
	CK_ULONG key_length = 2048;
	CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY, privateClass = CKO_PRIVATE_KEY;
	 


	
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0
	};

	CK_ATTRIBUTE publicKeyTemplate[]={
		
		{CKA_CLASS, &publicClass, sizeof(publicClass)},
		{CKA_TOKEN, &istrue, sizeof(istrue)},
		{CKA_LABEL, "${label}.pub",sizeof(label)-1},
		{CKA_MODULUS_BITS, &key_length, sizeof(key_length)},
		{CKA_VERIFY, &istrue, sizeof(istrue)}
	};

	CK_ATTRIBUTE privateKeyTemplate[]={
		{CKA_CLASS, &privateClass, sizeof(privateClass)},
		{CKA_TOKEN, &istrue, sizeof(istrue)},
		{CKA_LABEL, label, sizeof(label)-1},
		{CKA_SIGN, &istrue, sizeof(istrue)}
	};


	CK_RV rv = CKR_OK;
	CK_BYTE application;
	CK_SESSION_HANDLE hSession;
	CK_UTF8CHAR Pin[] = {"123456"};
	application = 1;

	rv = p11_functions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, &application, FALSE, &hSession);
	if(rv != CKR_OK){
		logger(rv,"C_OpenSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_Login(hSession,CKU_USER,Pin,sizeof(Pin)-1);
	if(rv != CKR_OK){
		logger(rv,"C_Login() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions-> C_GenerateKeyPair(hSession,&mechanism,publicKeyTemplate,sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE),privateKeyTemplate,sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE),&hPublicKey,&hPrivateKey);
	if(rv != CKR_OK){
		logger(rv,"C_GenerateKeyPair() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	rv = p11_functions->C_Logout(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_Logout() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_CloseSession(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_CloseSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	printf("Keypair created succesfully!");

	exit:
		return rv;
}

CK_RV generate_key_aes(CK_SLOT_ID slotID){
	CK_SESSION_HANDLE hSession;
	CK_OBJECT_HANDLE hKey;
	CK_ULONG key_length = 32;
	CK_CHAR label[] = {"AES_Key"};
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_MECHANISM mechanism = {
		CKM_AES_KEY_GEN, NULL_PTR, 0
	};

	CK_RV rv = CKR_OK;
	CK_UTF8CHAR Pin[] = {"123456"};
	CK_BYTE application;
	application = 1;

	CK_ATTRIBUTE AES_Template[]={
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_TOKEN, &istrue, sizeof(istrue)},
		{CKA_LABEL, label, sizeof(label) -1},
		{CKA_ENCRYPT, &istrue, sizeof(istrue)},
		{CKA_DECRYPT, &istrue, sizeof(istrue)},
		{CKA_VALUE_LEN, &key_length, sizeof(key_length)}
	};

	rv = p11_functions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, &application, FALSE, &hSession);
	if(rv != CKR_OK){
		logger(rv,"C_OpenSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_Login(hSession,CKU_USER,Pin,sizeof(Pin)-1);
	if(rv != CKR_OK){
		logger(rv,"C_Login() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_GenerateKey(hSession,&mechanism,AES_Template,sizeof(AES_Template)/sizeof(CK_ATTRIBUTE),&hKey);
	if(rv != CKR_OK){
		logger(rv,"C_GenerateKey() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_Logout(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_Logout() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	rv = p11_functions->C_CloseSession(hSession);
	if(rv != CKR_OK){
		logger(rv,"C_CloseSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	printf("\nAES Key created succefsully\n");
	exit:
		return rv;

}


CK_RV finalize(){
	CK_RV rv = CKR_OK;
	rv = p11_functions-> C_Finalize(NULL_PTR);
		if(rv != CKR_OK){
		logger(rv,"C_Finalize failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	exit:
		return rv;
}

int main(){

	int option = 0; 
	load_pkcs11_funtions();
	
	while(TRUE){
	printf("\nType number for function:\n");
	printf("1: get Number of avaible Slots\n");
	printf("2: init token\n");
	printf("3: Init User Pin\n");
	printf("4: Generate RSA Key Pair\n");
	printf("5: Generate AES Key\n");	
	printf("6: finalize\n");
	
	scanf("%d",&option);
	 switch (option)
	 {
	 case 1:
	 get_slot_num();
		break;
	case 2:
	initilaize_token(0);
		break;
	case 3:
	init_pin(0);
		break;
	case 4:
	generate_key_pair_rsa(0);
		break;
	case 5:
	generate_key_aes(0);
		break;
	case 6:
	finalize();
	return FALSE;
		break;
	
	default:
		break;
	 }
	
	}

}