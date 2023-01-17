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

/*Makros*/
#define MAX_PWD_LEN  200
#define MAX_LABEL_LEN  200
/* Global variables */
char cryptoki_lib_dest[4096] = {0};
CK_FUNCTION_LIST_PTR p11_functions = NULL_PTR;

void logger(int err, char *msg, int line, const char* file, const char *func)
{
	printf("\n0x%x : %s : %s : %s : %d \n",err,msg,func,file,line);
}

CK_RV get_library()
{
	CK_RV err = CKR_OK;
	char *lib_path = NULL;
	char *lib_name = NULL;

	lib_path = getenv("CRYPTOKI_LIB_PATH");
	if( lib_path == NULL )
	{
		printf("Failed to get CRYPTOKI_LIB_PATH");
		err = CKR_GENERAL_ERROR;
		goto exit;
	}

	lib_name = getenv("CRYPTOKI_LIB_NAME");
	if (lib_name == NULL)
	{
		err = CKR_GENERAL_ERROR;
		logger(err,"Failed to get CRYPTOKI_LIB_NAME",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

	snprintf(cryptoki_lib_dest,sizeof(cryptoki_lib_dest)-1,"%s/%s",lib_path,lib_name);

	printf("\n Cryptoki will load the library: %s \n",cryptoki_lib_dest);

	exit:
		return err;
}
CK_RV load_pkcs11_funtions(){
	CK_RV err = CKR_OK;
	//CK_C_GetFunctionList function_symbol_list = NULL;

	err= get_library();
	if ( err != CKR_OK){
		logger(err,"get_libary() failed",__LINE__,__FILE__,__FUNCTION__);
		goto exit;
	}

		/* Initialize PKCS 11 function library */
	if(p11_functions)
	{
		err = p11_functions->C_Initialize(NULL_PTR);
		if( err != CKR_OK )
		{
			logger(err,"C_Initialize() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}
	}
	exit:
		return err;
}

CK_RV initilaize_token(CK_SLOT_ID init_slot_id){
	CK_RV err = CKR_OK;
	CK_BYTE so_password[MAX_PWD_LEN]={0};
	CK_BYTE token_label[MAX_LABEL_LEN]={0};
	//unsigned int so_password_len = 0;

	printf("Enter new token label: ");
	scanf("%s",token_label);
	printf("Enter new SO password: ");

	getchar();
	scanf("%s",so_password);

	if(p11_functions){
		err = p11_functions->C_Initialize(NULL_PTR);
		if(err != CKR_OK){
			logger(err,"C_Initialize() failed",__LINE__,__FILE__,__FUNCTION__);
			goto exit;
		}
	}
	printf("\nToken initialized succesfully \n");
	exit:
		return err;
}


int main(){
	get_library();
	load_pkcs11_funtions();
	initilaize_token(1);
}