#pragma once

#include <windows.h>
#include <WinTrust.h>

#include <string>
#include <vector>



class SignatureInfo
{
private:
	DWORD lastError_;
	HCERTSTORE certStore_;
	HCRYPTMSG cryptMsg_;

	CMSG_SIGNER_INFO* subjectSignerInfoPtr_;
	CMSG_SIGNER_INFO* counterSignerInfoPtr_;

	PCCERT_CONTEXT singerCertContext_;
	PCCERT_CONTEXT counterCertContext_;

	WCHAR* subjectName_;
	WCHAR* issureName_;
	WCHAR* subjectRDN_;
	WCHAR* hashAlgorithm_;
	WCHAR* thumbPrint_;

	SignatureInfo* parent_;
	SignatureInfo* counterSignatures_;

public:
	SignatureInfo();
	~SignatureInfo();

	VOID Finish();
	WCHAR* GetNameString(PCCERT_CONTEXT certContext, DWORD certNameType, DWORD certFlag);
	WCHAR* GetSubjectName();
	WCHAR* GetIssureName();
	WCHAR* GetSubjectRDN();
	WCHAR* GetHashAlgorithm();
	WCHAR* GetThumbPrint(ALG_ID algID = CALG_SHA1);

	SignatureInfo* GetParent();
	SignatureInfo* GetCounterSignatures();

	VOID SetParent(SignatureInfo* siPtr);
	VOID SetCounterSignatures(SignatureInfo* siPtr);

	BOOL InitValue(LPBYTE dataContent, DWORD dataSize);
	BOOL InitValue(HCRYPTMSG cryptMsg, HCERTSTORE certStore);

	BOOL SetSubjectSignerInfo();
	CMSG_SIGNER_INFO* GetSubjectSignerInfo();

	BOOL SetCounterSignerInfo(LPBYTE dataContent, DWORD dataSize);
	BOOL SetCounterSignerInfo(CMSG_SIGNER_INFO* signerInfoPtr);

	BOOL ReadDetailInfo();

	BOOL InitFromCertContext(PCCERT_CONTEXT certContext_);
};


class FileSignature
{
//private:
public:
	DWORD lastError_;

	std::vector<SignatureInfo*> embeddedSignatures_;
	std::vector<SignatureInfo*> catalogSignatures_;

public:
	FileSignature();
	~FileSignature();

	//////////////////////////////For Embedded Signature//////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////
	static BOOL LoadFile(WCHAR* filePath, HCRYPTMSG& cryptMsg, HCERTSTORE& certStore);
	BOOL VerifyEmbeddedSignature(LPWSTR filePath);

	///////////////////////////////For Catalog Signature//////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////

	BOOL CalcHashFromFileHandle(HCATADMIN catAdmin, HANDLE hFile, BYTE** fileHashPPtr, ULONG* fileHashLengthPtr);
	BOOLEAN GetSignaturesFromStateData(_In_ HANDLE StateData,
		_Out_ PCERT_CONTEXT** Signatures, _Out_ PULONG NumberOfSignatures);
	LONG VerifyCatCertInfo(WINTRUST_CATALOG_INFO* catInfo,
		PCERT_CONTEXT** certContexts, PULONG NumberOfCertContexts, BOOL checkRevocation);
	BOOL VerifyCatalogSignature(LPWSTR filePath);
};


class FileProperty
{
//private:
public:
	FileSignature signInfo_;

	WCHAR	fileDescription_[MAX_PATH * 2];
	WCHAR	fileVersion_[MAX_PATH];
	WCHAR	internalName_[MAX_PATH];
	WCHAR	companyName_[MAX_PATH];
	WCHAR	productName_[MAX_PATH];
	WCHAR	productVersion_[MAX_PATH];
	WCHAR	copyRight_[MAX_PATH];
	WCHAR	language_[MAX_PATH];
	WCHAR	fixedFileVersion_[MAX_PATH];
	WCHAR	fixedProductVersion_[MAX_PATH];

	// Hash

public:
	FileProperty();
	~FileProperty();

	BOOL ExtractVersionInfo(IN PVOID pVersionInfo, IN WCHAR* pszInfoName, 
		OUT WCHAR* pszInformation, IN ULONG cchInformation);
	BOOL ExtractLangInfo(IN PVOID	pVersionInfo, OUT WCHAR* pszInformation, IN ULONG cchInformation);
	BOOL ExtractFixedVersionInfo(IN PVOID pVersionInfo, IN WCHAR* pszInfoName,
		OUT WCHAR* pszInformation, IN ULONG cchInformation, OUT PULARGE_INTEGER pVersionInt);
	BOOL GetProperty(WCHAR* filePath);

	BOOL LoadPeFile(WCHAR* filePath);
};