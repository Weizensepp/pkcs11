/* A PKCS#11 API for HSMs
*
* Author: Ferdinand Pohl
*
*/

/* Inlcudes */

#include "pkcs11.h"
#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <termios.h>


/*Makros*/
#define MAX_PWD_LEN  15
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
		rv = CKR_GENERAL_ERROR;
		logger(rv,"Failed to get CRYPTOKI_LIB_PATH",__LINE__,__FILE__,__FUNCTION__);
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

CK_RV get_slot_num(CK_ULONG *ulSlot_count){
	
	CK_RV rv = CKR_OK;
//	CK_BBOOL token_present = CK_TRUE;
	// CK_SLOT_ID_PTR pSlot_List;
	
	rv = p11_functions -> C_GetSlotList(CK_FALSE,NULL_PTR,ulSlot_count);
	if( rv != CKR_OK )
	{
		logger(rv,"C_GetSlotList() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	// if(rv == CKR_OK){
	// 	pSlot_List = (CK_SLOT_ID_PTR) malloc(ulSlot_count*sizeof(CK_SLOT_ID));
	// 	rv = p11_functions->C_GetSlotList(CK_FALSE, pSlot_List, &ulSlot_count);
	// 	if(rv == CKR_OK){
	// 		printf("\nAvailable Slots: %ld \n",ulSlot_count);
	// 	}
	// 	free(pSlot_List);
	// }
	
	exit:
		return rv;
}

CK_RV get_slot_list(CK_ULONG *max_slot_count,CK_SLOT_ID **slot_list)
{
	CK_RV rv = CKR_OK;
	CK_BBOOL token_present = TRUE;

	/*  Allocate slot ids to slot_list buffer and max no of slots */
	rv = p11_functions->C_GetSlotList(token_present,*slot_list,max_slot_count);
	if( rv != CKR_OK )
	{
		logger(rv,"C_GetSlotList() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	exit:
		return rv;
}

CK_RV get_token_info(CK_SLOT_ID slot_id, CK_TOKEN_INFO *token_info)
{
	CK_RV rv = CKR_OK;

	/* Get info of token available at slot_id */
	rv = p11_functions->C_GetTokenInfo(slot_id,token_info);
	if( rv != CKR_OK)
	{
		logger(rv,"C_GetTokenInfo() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	exit:
		return rv;
}

CK_RV initialize_token(CK_SLOT_ID slotID){
	
	CK_RV rv = CKR_OK;
	CK_UTF8CHAR soPin[MAX_PWD_LEN]={0};
	CK_UTF8CHAR label[32];

	//memset(&label, " ", sizeof(label));
	memcpy(&label, "ClypeumToken", strlen("ClypeumToken"));

	//memset(pin,0,sizeof(pin));
	printf("\nPlease Enter new SO Pin: ");

	getchar();
	getPin(soPin);
	printf("\n");

	rv = p11_functions->C_InitToken(slotID,soPin,sizeof(soPin)-1,label);
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
	CK_UTF8CHAR newPin[MAX_PWD_LEN]= {"0"};
	CK_UTF8CHAR soPin[MAX_PWD_LEN] = {"0"};
	CK_RV rv = CKR_OK;

	application = 1;

	printf("\nPlease Enter SO Pin: ");
	
	getchar();
	getPin(soPin);
	printf("\n");

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

	printf("\nPlease Enter new Pin: ");
	//getchar();
	getPin(newPin);
	printf("\n");

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
	CK_ULONG key_length = 1024;
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
	CK_UTF8CHAR pin[MAX_PWD_LEN] = {"0"};
	application = 1;

	rv = p11_functions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, &application, FALSE, &hSession);
	if(rv != CKR_OK){
		logger(rv,"C_OpenSession() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}
	
	printf("\nPlease Enter User Pin: ");
	getchar();
	getPin(pin);
	printf("\n");

	rv = p11_functions->C_Login(hSession,CKU_USER,pin,sizeof(pin)-1);
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
	printf("\nKeypair created succesfully!");

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
	CK_UTF8CHAR Pin[MAX_PWD_LEN] = {"0"};
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

	printf("\nPlease Enter User Pin: ");
	getchar();
	getPin(Pin);
	printf("\n");

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

void getPin(unsigned char *pin){
	
	static struct termios standard_term, actual_term;
	int i = 0;
	int c;
	/*saving old settings of terminal*/
	tcgetattr(STDIN_FILENO, &standard_term);
	actual_term = standard_term;

	/*turns off Echo*/
	actual_term.c_lflag &= ~(ECHO);

	/*setting new bits*/
	tcsetattr(STDIN_FILENO, TCSANOW, &actual_term);

	/*reading pin from console*/

	while((c = getchar()) != '\n' && i < MAX_PWD_LEN){
		pin[i++] = c;
	}
	pin[i]= '\0';

	/*resetting to old terminal settings*/
	tcsetattr(STDIN_FILENO, TCSANOW, &standard_term);
}

int main(){

	int option = 0; 
	load_pkcs11_funtions();
	CK_RV rv = CKR_OK;

	
	while(TRUE){
	printf("\nType number for function:\n");
	printf("1: Get slot list\n");
	printf("2: Token info\n");
	printf("3: Init token\n");
	printf("4: Init User Pin\n");
	printf("5: Generate RSA Key Pair\n");
	printf("6: Generate AES Key\n");	
	printf("7: Finalize\n");
	
	scanf("%d",&option);
	switch (option)
	{
	case 1:
	{
	CK_ULONG slot_count = 0;
	CK_ULONG max_slot_count = 0;
	CK_SLOT_ID *slot_list = NULL;
	CK_ULONG slot_iterator = 0;

	/* List number of available slots id with tokens*/
	rv = get_slot_num(&slot_count);
	if (rv != CKR_OK) {
		logger(rv, "get_count_available_slots() failed", __LINE__,__FILE__, __FUNCTION__);
		goto exit;
	}
	/* Assign memory to slot_id buffer to store list of slot list of slot ids */
	slot_list = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slot_count);
	max_slot_count = slot_count;

	/* Get slot list */
	rv = get_slot_list(&max_slot_count, &slot_list);
	if (rv != CKR_OK)
	{
		logger(rv, "get_slot_list() failed", __LINE__, __FILE__,__FUNCTION__);
		goto exit;
	}

	/* Verify new count to slot does not exceed slots previously detected */
	if (slot_count > max_slot_count)
	{
		printf("Second call to C_GetSlotList returned number of present slots(%ld) larger than previously detected(%ld)",max_slot_count, slot_count);
	}

	printf("\nList of available slot ids with tokens: \n");

	/* Get info of each slot */
	for (slot_iterator = 0; slot_iterator < max_slot_count; slot_iterator++)
	{
		printf("\nSlot #%ld\n", slot_list[slot_iterator]);
	}

	break;
	}
	case 2:
	{
	CK_TOKEN_INFO token_info ;
	CK_SLOT_ID slot_id = 0 ;
	char buffer[100] ={0};

	printf("\nEnter slot id: ");
	scanf("%ld",&slot_id);

	get_token_info(slot_id,&token_info);

	printf("Token information: \n");
	snprintf(buffer,sizeof(token_info.label),"%s",token_info.label);
	printf("->label: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.manufacturerID),"%s",token_info.manufacturerID);
	printf("->Manufacturer: %s\n",buffer);


	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.model),"%s",token_info.model);
	printf("->Model: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.serialNumber),"%s",token_info.serialNumber);
	printf("->Serial number: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.ulTotalPublicMemory),"%ld",token_info.ulTotalPublicMemory);
	printf("->Total public memory: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.ulFreePublicMemory),"%ld",token_info.ulFreePublicMemory);
	printf("->Total free public memory: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.ulSessionCount),"%ld",token_info.ulSessionCount);
	printf("->Session count: %s\n",buffer);

	memset(buffer,0,sizeof(buffer));
	snprintf(buffer,sizeof(token_info.ulMaxSessionCount),"%ld",token_info.ulMaxSessionCount);
	printf("->Max Session count: %s\n",buffer);

	/* Check flags */
	if( token_info.flags & CKF_RNG)
	{
		printf("->Token has its own random number generator \n");
	}
	else
	{
		printf("->Token does not have its own random number generator \n");
	}

	if( token_info.flags & CKF_WRITE_PROTECTED)
	{
		printf("->Token is write protected\n");
	}
	else
	{
		printf("->Token is not write protected \n");
	}

	if( token_info.flags & CKF_TOKEN_INITIALIZED)
	{
		printf("->Token is initialized\n");
	}
	else
	{
		printf("->Token is not initialized \n");
	}

	break;
}
	case 3:
	{
	CK_SLOT_ID slotID = 0;
	printf("Select a Slot: ");
	scanf("%ld", &slotID);
	initialize_token(slotID);
		break;
	}
	case 4:
	{
	CK_SLOT_ID slotID = 0;
	printf("Select a Slot: ");
	scanf("%ld", &slotID);
	init_pin(slotID);
		break;
	}
	case 5:
	{
	CK_SLOT_ID slotID = 0;
	printf("Select a Slot: ");
	scanf("%ld", &slotID);
	generate_key_pair_rsa(slotID);
		break;
	}
	case 6:
	{
	CK_SLOT_ID slotID = 0;
	printf("Select a Slot: ");
	scanf("%ld", &slotID);
	generate_key_aes(slotID);
		break;
	}
	case 7:
	finalize();
	return FALSE;
		break;
	
	default:
		break;
	 }
	
	}
	exit:
		return rv;
}