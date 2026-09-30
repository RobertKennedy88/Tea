#include "FileProperty.h"


#include <SoftPub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <versionhelpers.h>
#include <strsafe.h>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")


SignatureInfo::SignatureInfo()
{
	lastError_ = 0;
	certStore_ = NULL;
	cryptMsg_ = NULL;

	subjectSignerInfoPtr_ = NULL;
	counterSignerInfoPtr_ = NULL;

	singerCertContext_ = NULL;
	counterCertContext_ = NULL;

	subjectName_ = NULL;
	issureName_ = NULL;
	subjectRDN_ = NULL;
	hashAlgorithm_ = NULL;
	thumbPrint_ = NULL;

	parent_ = NULL;
	counterSignatures_ = NULL;
}
SignatureInfo::~SignatureInfo()
{
	Finish();
}
VOID SignatureInfo::Finish()
{
	if (certStore_ != NULL)
	{
		CertCloseStore(certStore_, 0);
		certStore_ = NULL;
	}
	if (cryptMsg_ != NULL)
	{
		CryptMsgClose(cryptMsg_);
		cryptMsg_ = NULL;
	}

	if (subjectSignerInfoPtr_ != NULL)
	{
		LocalFree(subjectSignerInfoPtr_);
		subjectSignerInfoPtr_ = NULL;
	}
	if (counterSignerInfoPtr_ != NULL)
	{
		LocalFree(counterSignerInfoPtr_);
		counterSignerInfoPtr_ = NULL;
	}

	if (singerCertContext_ != NULL)
	{
		CertFreeCertificateContext(singerCertContext_);
		singerCertContext_ = NULL;
	}
	if (counterCertContext_ != NULL)
	{
		CertFreeCertificateContext(counterCertContext_);
		counterCertContext_ = NULL;
	}

	if (subjectName_ != NULL)
	{
		LocalFree(subjectName_);
		subjectName_ = NULL;
	}
	if (issureName_ != NULL)
	{
		LocalFree(issureName_);
		issureName_ = NULL;
	}
	if (subjectRDN_ != NULL)
	{
		LocalFree(subjectRDN_);
		subjectRDN_ = NULL;
	}
	if (hashAlgorithm_ != NULL)
	{
		LocalFree(hashAlgorithm_);
		hashAlgorithm_ = NULL;
	}
	if (thumbPrint_ != NULL)
	{
		LocalFree(thumbPrint_);
		thumbPrint_ = NULL;
	}

	if (parent_ != NULL)
	{
		delete parent_;
		parent_ = NULL;
	}
	if (counterSignatures_ != NULL)
	{
		delete counterSignatures_;
		counterSignatures_ = NULL;
	}
}

WCHAR* SignatureInfo::GetNameString(PCCERT_CONTEXT certContext, DWORD certNameType, DWORD certFlag)
{
	DWORD funcResult = 0;
	WCHAR* certNameString = NULL;
	DWORD certNameLength = 0;

	if (certContext == NULL)
		return NULL;

	certNameLength = CertGetNameString(certContext, certNameType, certFlag, NULL, NULL, 0);
	if (certNameLength == NULL)
		return NULL;

	certNameString = (LPWSTR)LocalAlloc(LPTR, certNameLength * sizeof(WCHAR) + sizeof(WCHAR));
	if (certNameString == NULL)
		return NULL;

	certNameLength = CertGetNameString(certContext, certNameType, certFlag, NULL, certNameString, certNameLength);
	if (certNameLength == NULL)
		return NULL;

	return certNameString;
}
WCHAR* SignatureInfo::GetSubjectName()
{
	if (subjectName_ == NULL)
		subjectName_ = GetNameString(singerCertContext_, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);

	return subjectName_;
}
WCHAR* SignatureInfo::GetIssureName()
{
	if (issureName_ == NULL)
		issureName_ = GetNameString(singerCertContext_, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);

	return issureName_;
}
WCHAR* SignatureInfo::GetSubjectRDN()
{
	if (subjectRDN_ == NULL)
		subjectRDN_ = GetNameString(singerCertContext_, CERT_NAME_RDN_TYPE, 0);

	return subjectRDN_;
}
WCHAR* SignatureInfo::GetHashAlgorithm()
{
	if (hashAlgorithm_ == NULL)
	{
		if (subjectSignerInfoPtr_ == NULL) return NULL;

		DWORD algorithmLen = strlen(subjectSignerInfoPtr_->HashAlgorithm.pszObjId);

		hashAlgorithm_ = (WCHAR*)LocalAlloc(LPTR, algorithmLen * sizeof(WCHAR) + sizeof(WCHAR));
		if (hashAlgorithm_ == NULL)
			return NULL;

		MultiByteToWideChar(CP_ACP, 0, subjectSignerInfoPtr_->HashAlgorithm.pszObjId, -1,
			hashAlgorithm_, algorithmLen + 1);
	}

	return hashAlgorithm_;
	// 1.3.14.3.2.26 SHA1
	// 2.16.840.1.101.3.4.2.1 SHA2
}

WCHAR* SignatureInfo::GetThumbPrint(ALG_ID algID)
{
	if (thumbPrint_ == NULL)
	{
		BYTE	hashValue[1024] = { 0, };
		DWORD	hashLength = sizeof(hashValue);

		if (singerCertContext_ == NULL) return NULL;

		if (CryptHashCertificate(NULL, algID, 0, singerCertContext_->pbCertEncoded,
			singerCertContext_->cbCertEncoded, hashValue, &hashLength) == FALSE)
		{
			lastError_ = GetLastError();
			return NULL;
		}

		thumbPrint_ = (WCHAR*)LocalAlloc(LPTR, hashLength * sizeof(WCHAR) * 2 + 32);
		if (thumbPrint_ == NULL)
		{
			lastError_ = GetLastError();
			return NULL;
		}

		for (DWORD index = 0; index < hashLength; index++)
		{
			swprintf(thumbPrint_ + index * 2, hashLength * 2 + 32 - index * 2, L"%02X", hashValue[index]);
		}
	}
	return thumbPrint_;
}

SignatureInfo* SignatureInfo::GetParent()
{
	return parent_;
}
SignatureInfo* SignatureInfo::GetCounterSignatures()
{
	return counterSignatures_;
}
VOID SignatureInfo::SetParent(SignatureInfo* siPtr)
{
	parent_ = siPtr;;
}
VOID SignatureInfo::SetCounterSignatures(SignatureInfo* siPtr)
{
	counterSignatures_ = siPtr;
}
BOOL SignatureInfo::InitValue(LPBYTE dataContent, DWORD dataSize)
{
	DWORD	signerInfoSize = 0;
	BOOL	ret = FALSE;

	if (dataContent == NULL || dataSize == 0)
		return FALSE;

	cryptMsg_ = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, 0, NULL, 0);
	if (cryptMsg_ == NULL)
	{
		lastError_ = GetLastError();
		return FALSE;
	}
	ret = CryptMsgUpdate(
		cryptMsg_,
		dataContent,
		dataSize,
		TRUE);
	if (ret == FALSE)
	{
		lastError_ = GetLastError();
		return FALSE;
	}
	certStore_ = CertOpenStore(
		CERT_STORE_PROV_MSG,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		NULL,
		NULL,
		cryptMsg_);
	if (certStore_ == NULL)
	{
		lastError_ = GetLastError();
		return FALSE;
	}

	return TRUE;
}
BOOL SignatureInfo::InitValue(HCRYPTMSG cryptMsg, HCERTSTORE certStore)
{
	cryptMsg_ = cryptMsg;
	certStore_ = certStore;
	return TRUE;
}
BOOL SignatureInfo::SetSubjectSignerInfo()
{
	DWORD	signerInfoSize = 0;
	BOOL	ret = FALSE;

	ret = CryptMsgGetParam(cryptMsg_, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize);
	if (ret == FALSE || signerInfoSize == 0)
	{
		lastError_ = GetLastError();
		return FALSE;
	}
	// Allocate Message Buffer
	subjectSignerInfoPtr_ = (CMSG_SIGNER_INFO*)LocalAlloc(LPTR, signerInfoSize);
	if (subjectSignerInfoPtr_ == NULL)
	{
		lastError_ = GetLastError();
		return FALSE;
	}
	// Get Message Info
	ret = CryptMsgGetParam(cryptMsg_, CMSG_SIGNER_INFO_PARAM, 0, subjectSignerInfoPtr_, &signerInfoSize);
	if (ret == FALSE)
	{
		lastError_ = GetLastError();
		return FALSE;
	}
	return TRUE;
}
CMSG_SIGNER_INFO* SignatureInfo::GetSubjectSignerInfo()
{
	return subjectSignerInfoPtr_;
}
BOOL SignatureInfo::SetCounterSignerInfo(LPBYTE dataContent, DWORD dataSize)
{
	DWORD	counterSingerSize = 0;
	BOOL	ret = FALSE;

	// Read Counter Signer Info // Counter Signer Information
	ret = CryptDecodeObject(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		PKCS7_SIGNER_INFO,
		dataContent,
		dataSize,
		0, NULL,
		&counterSingerSize);
	if (ret == TRUE)
	{
		counterSignerInfoPtr_ = (CMSG_SIGNER_INFO*)LocalAlloc(LPTR, counterSingerSize);
		if (counterSignerInfoPtr_ != NULL)
		{
			ret = CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				PKCS7_SIGNER_INFO,
				dataContent,
				dataSize,
				0,
				counterSignerInfoPtr_,
				&counterSingerSize);
		}
	}
	return ret;
}
BOOL SignatureInfo::SetCounterSignerInfo(CMSG_SIGNER_INFO* signerInfoPtr)
{
	counterSignerInfoPtr_ = signerInfoPtr;
	return TRUE;
}
BOOL SignatureInfo::ReadDetailInfo()
{
	CERT_INFO certInfo = { 0, };

	if (subjectSignerInfoPtr_ != NULL && certStore_ != NULL)
	{
		certInfo.Issuer = subjectSignerInfoPtr_->Issuer;
		certInfo.SerialNumber = subjectSignerInfoPtr_->SerialNumber;

		singerCertContext_ = CertFindCertificateInStore(certStore_,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
		if (singerCertContext_ == NULL)
		{
			lastError_ = GetLastError();
			return FALSE;
		}
		GetSubjectName();
		GetIssureName();
		GetHashAlgorithm();
		GetThumbPrint(CALG_SHA1);
	}

	if (counterSignerInfoPtr_ != NULL && certStore_ != NULL)
	{
		certInfo.Issuer = counterSignerInfoPtr_->Issuer;
		certInfo.SerialNumber = counterSignerInfoPtr_->SerialNumber;

		counterCertContext_ = CertFindCertificateInStore(certStore_,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
		if (counterCertContext_ == NULL)
		{
			lastError_ = GetLastError();
			return FALSE;
		}
	}
	return TRUE;
}
BOOL SignatureInfo::InitFromCertContext(PCCERT_CONTEXT certContext_)
{
	singerCertContext_ = certContext_;

	GetSubjectName();
	GetIssureName();
	GetThumbPrint(CALG_SHA1);

	return TRUE;
}

FileSignature::FileSignature()
{
	lastError_ = 0;

	embeddedSignatures_.clear();
	catalogSignatures_.clear();
}
FileSignature::~FileSignature()
{
	for (SignatureInfo* eachSignature1 : embeddedSignatures_)
	{
		//eachSignature1->Finish();
		delete eachSignature1;
	}
	embeddedSignatures_.clear();

	for (SignatureInfo* eachSignature2 : catalogSignatures_)
	{
		//eachSignature2->Finish();
		delete eachSignature2;
	}
	catalogSignatures_.clear();
}

BOOL FileSignature::LoadFile(WCHAR* filePath, HCRYPTMSG& cryptMsg, HCERTSTORE& certStore)
{
	DWORD	msgAndCertEncodingType = 0;	//  Encoding Type is 65537, PKCS#7, 1 is X.509
	DWORD	contentType = 0;
	DWORD	formatType = 0;

	certStore = NULL;
	cryptMsg = NULL;

	try
	{
		// Create Certificate Object
		if (CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			filePath,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&msgAndCertEncodingType,
			&contentType,
			&formatType,
			&certStore,
			&cryptMsg,
			NULL) == FALSE)
		{
			// Certificate Object Fail
			return FALSE;
		}
	}
	catch (...)
	{
		return FALSE;
	}
	return TRUE;
}
BOOL FileSignature::VerifyEmbeddedSignature(LPWSTR filePath)
{
	try
	{
		SignatureInfo* firstSignatureInfo = NULL;
		HCRYPTMSG cryptMsg = NULL;
		HCERTSTORE certStore = NULL;
		CMSG_SIGNER_INFO* signerInfoPtr;

		if (LoadFile(filePath, cryptMsg, certStore) == FALSE)
			return FALSE;

		firstSignatureInfo = new SignatureInfo();

		if (firstSignatureInfo->InitValue(cryptMsg, certStore) == FALSE ||
			firstSignatureInfo->SetSubjectSignerInfo() == FALSE)
			return FALSE;

		signerInfoPtr = firstSignatureInfo->GetSubjectSignerInfo();
		if (signerInfoPtr == NULL)
			return FALSE;

		for (DWORD index = 0; index < signerInfoPtr->UnauthAttrs.cAttr; index++)
		{
// 			if (lstrcmpA(signerInfoPtr->UnauthAttrs.rgAttr[index].pszObjId, szOID_RSA_counterSign) == 0)
// 			{
// 				firstSignatureInfo->SetCounterSignerInfo(
// 					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].pbData,
// 					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].cbData);
// 				continue;
// 			}
// 			if (lstrcmpA(signerInfoPtr->UnauthAttrs.rgAttr[index].pszObjId, szOID_RFC3161_counterSign) == 0)
// 			{
// 				SignatureInfo* counterSignatureInfoPtr = NULL;
// 				
// 				counterSignatureInfoPtr = new SignatureInfo();
// 				
// 				if (counterSignatureInfoPtr->InitValue(
// 					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].pbData,
// 					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].cbData) == TRUE &&
// 					counterSignatureInfoPtr->SetSubjectSignerInfo() ==  TRUE)
// 				{
// 					firstSignatureInfo->SetCounterSignerInfo(counterSignatureInfoPtr->GetSubjectSignerInfo());
// 					firstSignatureInfo->SetCounterSignatures(counterSignatureInfoPtr);
// 				}
// 				continue;
// 			}
			if (lstrcmpA(signerInfoPtr->UnauthAttrs.rgAttr[index].pszObjId, szOID_NESTED_SIGNATURE) == 0)
			{
				SignatureInfo* nextSignatureInfoPtr = NULL;

				nextSignatureInfoPtr = new SignatureInfo();

				if (nextSignatureInfoPtr->InitValue(
					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].pbData,
					signerInfoPtr->UnauthAttrs.rgAttr[index].rgValue[0].cbData) == TRUE &&
					nextSignatureInfoPtr->SetSubjectSignerInfo() == TRUE)
				{
					nextSignatureInfoPtr->ReadDetailInfo();
					embeddedSignatures_.push_back(nextSignatureInfoPtr);
				}
				continue;
			}
		}
		firstSignatureInfo->ReadDetailInfo();
		embeddedSignatures_.push_back(firstSignatureInfo);
	}
	catch (...)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL FileSignature::CalcHashFromFileHandle(HCATADMIN catAdmin, HANDLE hFile, BYTE** fileHashPPtr, ULONG* fileHashLengthPtr)
{
	BOOL		ret = FALSE;
	BYTE* fileHash = NULL;
	ULONG		hashLength = 0;

	CryptCATAdminCalcHashFromFileHandle2(catAdmin, hFile, &hashLength, fileHash, 0);
	if (hashLength == 0)
		goto FINAL;

	fileHash = (LPBYTE)LocalAlloc(LPTR, hashLength);
	if (fileHash == NULL)
		goto FINAL;

	ret = CryptCATAdminCalcHashFromFileHandle2(catAdmin, hFile, &hashLength, fileHash, 0);
	if (ret == FALSE)
		goto FINAL;

FINAL:
	if (fileHashLengthPtr)
		*fileHashLengthPtr = hashLength;

	if (fileHashPPtr)
		*fileHashPPtr = fileHash;

	return ret;
}
BOOLEAN FileSignature::GetSignaturesFromStateData(_In_ HANDLE StateData,
	_Out_ PCERT_CONTEXT** signaturesPPtr, _Out_ PULONG numberOfSignaturesPtr)
{
	PCRYPT_PROVIDER_DATA provData = NULL;
	PCRYPT_PROVIDER_SGNR sgnr = NULL;
	PCERT_CONTEXT* certContextPtr = NULL;
	ULONG i = 0;
	ULONG numberOfSignatures = 0;
	ULONG index = 0;

	provData = WTHelperProvDataFromStateData(StateData);
	if (!provData)
	{
		*signaturesPPtr = NULL;
		*numberOfSignaturesPtr = 0;
		return FALSE;
	}

	i = 0;
	numberOfSignatures = 0;

	while (sgnr = WTHelperGetProvSignerFromChain(provData, i, FALSE, 0))
	{
		if (sgnr->csCertChain != 0)
			numberOfSignatures++;
		i++;
	}

	if (numberOfSignatures != 0)
	{
		certContextPtr = (PCERT_CONTEXT*)LocalAlloc(LPTR, numberOfSignatures * sizeof(CERT_CONTEXT));
		i = 0;
		index = 0;

		while (sgnr = WTHelperGetProvSignerFromChain(provData, i, FALSE, 0))
		{
			if (sgnr->csCertChain != 0)
				certContextPtr[index++] = (PCERT_CONTEXT)CertDuplicateCertificateContext(sgnr->pasCertChain[0].pCert);

			i++;
		}
	}
	else
	{
		certContextPtr = NULL;
	}

	*signaturesPPtr = certContextPtr;
	*numberOfSignaturesPtr = numberOfSignatures;

	return TRUE;
}
LONG FileSignature::VerifyCatCertInfo(WINTRUST_CATALOG_INFO* catInfo,
	PCERT_CONTEXT** certContexts, PULONG numberOfCertContexts, BOOL checkRevocation)
{
	LONG status;
	WINTRUST_DATA trustData = { 0 };
	GUID DriverActionVerify = DRIVER_ACTION_VERIFY;

	trustData.cbStruct = sizeof(WINTRUST_DATA);
	trustData.pPolicyCallbackData = NULL;
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
	trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	trustData.pCatalog = catInfo;

	if (FALSE == checkRevocation)
	{
		trustData.fdwRevocationChecks = WTD_REVOKE_NONE;

		if (IsWindowsVistaOrGreater())
			trustData.dwProvFlags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
		else
			trustData.dwProvFlags |= WTD_REVOCATION_CHECK_NONE;
	}

	status = WinVerifyTrust(NULL, &DriverActionVerify, &trustData);
	if (status == ERROR_SUCCESS && trustData.hWVTStateData != NULL)
	{
		GetSignaturesFromStateData(trustData.hWVTStateData, certContexts, numberOfCertContexts);

		trustData.dwStateAction = WTD_STATEACTION_CLOSE;
		status = WinVerifyTrust(NULL, &DriverActionVerify, &trustData);
	}

	return status;
}
BOOL FileSignature::VerifyCatalogSignature(LPWSTR filePath)
{
	const GUID driverActionVerify = DRIVER_ACTION_VERIFY;

	HCATADMIN catAdmin = NULL;
	HCATINFO catInfo = NULL;
	CATALOG_INFO ci = { 0 };
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL ret = FALSE;
	BYTE* fileHash = NULL;
	PCERT_CONTEXT* certContexts = NULL;
	ULONG fileHashLength = 0, numberOfCertContexts = 0;
	DRIVER_VER_INFO verInfo = { 0 };
	WINTRUST_CATALOG_INFO catalogInfo = { 0 };
	LONG  funcResult = 0;
	

	if (CryptCATAdminAcquireContext2(&catAdmin, &driverActionVerify, BCRYPT_SHA1_ALGORITHM, NULL, 0) == FALSE)
		goto FINAL;

	hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE)
		goto FINAL;

	if (CalcHashFromFileHandle(catAdmin, hFile, &fileHash, &fileHashLength) == FALSE)
		goto FINAL;

	catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, fileHash, fileHashLength, 0, NULL);
	if (catInfo == NULL)
		goto FINAL;

	do
	{
		ret = CryptCATCatalogInfoFromContext(catInfo, &ci, 0);
		if (ret == FALSE)
			goto FINAL;

		verInfo.cbStruct = sizeof(DRIVER_VER_INFO);

		catalogInfo.cbStruct = sizeof(catalogInfo);
		catalogInfo.pcwszCatalogFilePath = ci.wszCatalogFile;
		catalogInfo.pcwszMemberFilePath = filePath;
		catalogInfo.pcwszMemberTag = NULL;
		catalogInfo.pbCalculatedFileHash = fileHash;
		catalogInfo.cbCalculatedFileHash = fileHashLength;
#if (NTDDI_VERSION >= NTDDI_WIN8)
		catalogInfo.hCatAdmin = catAdmin;		// optional for SHA-1 hashes, required for all other hash types.
#endif // #if (NTDDI_VERSION >= NTDDI_WIN8)
		funcResult = VerifyCatCertInfo(&catalogInfo, &certContexts, &numberOfCertContexts, FALSE);

		for (UINT index = 0; index < numberOfCertContexts; index++)
		{
			BOOL alreadyExist = FALSE;
			SignatureInfo* signInfoPtr = NULL;

			signInfoPtr = new SignatureInfo();
			signInfoPtr->InitFromCertContext(certContexts[index]);

			for (UINT junc = 0; junc < catalogSignatures_.size(); junc++)
			{
				if (_wcsicmp(catalogSignatures_[junc]->GetThumbPrint(), signInfoPtr->GetThumbPrint()) == 0)
					alreadyExist = TRUE;
			}

			if (alreadyExist == FALSE)
				catalogSignatures_.push_back(signInfoPtr);
		}

		if (certContexts)
		{
			LocalFree(certContexts);
			certContexts = NULL;
		}

		// 		if (funcResult == 0)
		// 			break;

		catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, fileHash, fileHashLength, 0, &catInfo);
	} while (catInfo);

	CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);

	ret = TRUE;
FINAL:
	if (catAdmin != NULL)
	{
		CryptCATAdminReleaseContext(catAdmin, 0);
		catAdmin = NULL;
	}
	if (fileHash != NULL)
	{
		LocalFree(fileHash);
		fileHash = NULL;
	}
	if (INVALID_HANDLE_VALUE != hFile)
		CloseHandle(hFile);

	return ret;
}



FileProperty::FileProperty()
{
	memset(fileDescription_, 0, sizeof(fileDescription_));
	memset(fileVersion_, 0, sizeof(fileVersion_));
	memset(internalName_, 0, sizeof(internalName_));
	memset(companyName_, 0, sizeof(companyName_));
	memset(productName_, 0, sizeof(productName_));
	memset(productVersion_, 0, sizeof(productVersion_));
	memset(copyRight_, 0, sizeof(copyRight_));
	memset(language_, 0, sizeof(language_));
	memset(fixedFileVersion_, 0, sizeof(fixedFileVersion_));
	memset(fixedProductVersion_, 0, sizeof(fixedProductVersion_));
}
FileProperty::~FileProperty()
{

}

BOOL FileProperty::ExtractVersionInfo(IN PVOID pVersionInfo, IN WCHAR* pszInfoName, OUT WCHAR* pszInformation, IN ULONG cchInformation)
{
	WCHAR		szVersionString[MAX_PATH] = { 0, };
	LPVOID		pVersion = NULL;
	LPCWSTR		lpSubBlock = L"\\VarFileInfo\\Translation";
	DWORD		uLength = 0, langD = 0;
	BOOL		retVal = FALSE;

	retVal = VerQueryValueW(pVersionInfo, lpSubBlock, (LPVOID*)&pVersion, (UINT*)&uLength);
	if (retVal && uLength == 4)
	{
		memcpy(&langD, pVersion, 4);

		StringCchPrintfW(szVersionString, _countof(szVersionString), L"\\StringFileInfo\\%02X%02X%02X%02X\\%s",
			(langD & 0xff00) >> 8, langD & 0xff, (langD & 0xff000000) >> 24,
			(langD & 0xff0000) >> 16, pszInfoName);
	}
	else
	{
		StringCchPrintfW(szVersionString, _countof(szVersionString),
			L"\\StringFileInfo\\%04X04B0\\%s", GetUserDefaultLangID(), pszInfoName);
	}

	if (VerQueryValueW(pVersionInfo, (LPCWSTR)szVersionString, (LPVOID*)&pVersion, (UINT*)&uLength))
	{
		StringCchCopy(pszInformation, cchInformation, (LPCWSTR)pVersion);
		retVal = TRUE;
	}

	return retVal;
}

BOOL FileProperty::ExtractLangInfo(IN PVOID	pVersionInfo, OUT WCHAR* pszInformation, IN ULONG cchInformation)
{
	LPVOID		pVersion = NULL;
	LPCWSTR		lpSubBlock = L"\\VarFileInfo\\Translation";
	DWORD		uLength = 0, LangId = 0;
	BOOL		retVal = FALSE;
	CHAR		PrimLang = 0;
	CHAR		SubLang = 0;
	INT			nResult = 0;

	retVal = VerQueryValueW(pVersionInfo, lpSubBlock, (LPVOID*)&pVersion, (UINT*)&uLength);
	if (retVal && uLength == 4)
	{
		memcpy(&LangId, pVersion, 4);
	}
	else
	{
		LangId = GetUserDefaultLangID();
	}

	nResult = GetLocaleInfo(MAKELCID(LangId & 0xffff, SORT_DEFAULT), LOCALE_SENGLANGUAGE, pszInformation, cchInformation);
	if (nResult == 0)
		goto FINAL;

	retVal = TRUE;

FINAL:
	return retVal;
}

BOOL FileProperty::ExtractFixedVersionInfo(IN PVOID	pVersionInfo, IN WCHAR* pszInfoName, OUT WCHAR* pszInformation, IN ULONG cchInformation, OUT PULARGE_INTEGER pVersionInt)
{
	BOOL		retValue = FALSE;
	LPBYTE		lpBuffer = NULL;
	UINT		size = 0;

	if (pVersionInfo == NULL || pszInfoName == NULL || pszInformation == NULL || pVersionInt == NULL)
		return retValue;

	if (VerQueryValueW(pVersionInfo, L"\\", (VOID FAR * FAR*) & lpBuffer, &size))
	{
		if (size != 0)
		{
			VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
			if (_wcsicmp(L"FileVersion", pszInfoName) == 0)
			{
				StringCchPrintf(pszInformation, cchInformation, L"%d.%d.%d.%d", HIWORD(verInfo->dwFileVersionMS), LOWORD(verInfo->dwFileVersionMS), HIWORD(verInfo->dwFileVersionLS), LOWORD(verInfo->dwFileVersionLS));
				if (pVersionInt != NULL)
				{
					pVersionInt->HighPart = verInfo->dwFileVersionMS;
					pVersionInt->LowPart = verInfo->dwFileVersionLS;
				}
				retValue = TRUE;
			}
			else if (_wcsicmp(L"ProductVersion", pszInfoName) == 0)
			{
				StringCchPrintf(pszInformation, cchInformation, L"%d.%d.%d.%d", HIWORD(verInfo->dwProductVersionMS), LOWORD(verInfo->dwProductVersionMS), HIWORD(verInfo->dwProductVersionLS), LOWORD(verInfo->dwProductVersionLS));
				if (pVersionInt != NULL)
				{
					pVersionInt->HighPart = verInfo->dwProductVersionMS;
					pVersionInt->LowPart = verInfo->dwProductVersionLS;
				}
				retValue = TRUE;
			}
		}
	}
	else
	{
		retValue = FALSE;
	}

	return retValue;
}

BOOL FileProperty::GetProperty(WCHAR* filePath)
{
	ULARGE_INTEGER	fixedFileVer, fixedProductVer;
	BOOL retValue = FALSE;
	DWORD		verHandle = 0;
	LPSTR		verData = NULL;

	DWORD		verSize = GetFileVersionInfoSize(filePath, &verHandle);
	if (verSize != 0)
	{
		verData = (LPSTR)LocalAlloc(LPTR, verSize);
		if (verData != NULL && GetFileVersionInfo(filePath, verHandle, verSize, verData) == TRUE)
		{
			ExtractVersionInfo(verData, (WCHAR*)L"FileDescription", fileDescription_, _countof(fileDescription_));
			ExtractVersionInfo(verData, (WCHAR*)L"CompanyName", companyName_, _countof(companyName_));
			ExtractVersionInfo(verData, (WCHAR*)L"ProductName", productName_, _countof(productName_));
			ExtractVersionInfo(verData, (WCHAR*)L"InternalName", internalName_, _countof(internalName_));
			ExtractVersionInfo(verData, (WCHAR*)L"LegalCopyright", copyRight_, _countof(copyRight_));
			ExtractVersionInfo(verData, (WCHAR*)L"FileVersion", fileVersion_, _countof(fileVersion_));
			ExtractVersionInfo(verData, (WCHAR*)L"ProductVersion", productVersion_, _countof(productVersion_));
			ExtractLangInfo(verData, language_, _countof(language_));

			ExtractFixedVersionInfo(verData, (WCHAR*)L"FileVersion", fixedFileVersion_, _countof(fixedFileVersion_), &fixedFileVer);
			ExtractFixedVersionInfo(verData, (WCHAR*)L"ProductVersion", fixedProductVersion_, _countof(fixedProductVersion_), &fixedProductVer);
		}
		if (verData)
			LocalFree(verData);
	}
	return TRUE;
}

BOOL FileProperty::LoadPeFile(WCHAR* filePath)
{
	GetProperty(filePath);

	if (signInfo_.VerifyEmbeddedSignature(filePath) == FALSE)
		signInfo_.VerifyCatalogSignature(filePath);

	return TRUE;
}
