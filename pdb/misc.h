#pragma once

#include <fpro.h>
#include <md5.h>

#define ASSERT(x) QASSERT(__LINE__, x)

inline qwstring utf8_utf16(const char * in)
{
	qwstring out;
	bool bResult = utf8_utf16(&out, in);
	ASSERT(bResult);
	return out;
}

inline qstring utf8_acp(const char * in)
{
	qstring out;
	bool bResult = change_codepage(&out, in, CP_UTF8, CP_ACP);
	ASSERT(bResult);
	return out;
}

inline qstring utf16_utf8(const wchar16_t * in)
{
	qstring out;
	bool bResult = utf16_utf8(&out, in);
	ASSERT(bResult);
	return out;
}

inline qstring utf16_acp(const wchar16_t * in)
{
	qstring utf8(utf16_utf8(in));
	qstring out(utf8_acp(utf8.c_str()));
	return out;
}

inline uint64 qfilesize_utf8(const char * fname_utf8)
{
	qwstring fname_utf16(utf8_utf16(fname_utf8));
	//qfilesize目前有BUG，内部未先将参数转换为ANSI格式，即使转换成ANSI格式也会有问题，不支持Unicode路径
	//qstat 也一样有这个问题
	//只有qfilelength没有这个问题，不过它需要打开文件，开销较大，所以我们不使用
	WIN32_FILE_ATTRIBUTE_DATA FileAttribData = { 0 };
	GetFileAttributesExW(fname_utf16.c_str(), GetFileExInfoStandard, &FileAttribData);
	LARGE_INTEGER RetValue = { FileAttribData.nFileSizeLow, (LONG)FileAttribData.nFileSizeHigh };
	return RetValue.QuadPart;
}

inline void MD5_FromData(const uchar* buf, unsigned int len, uchar digest[16])
{
	MD5Context ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, buf, len);
	MD5Final(digest, &ctx);
}

static qstring GetFileContext(const char* pszFileName, size_t& nFileSize, const char* pszMode = "rb")
{
	void* lpFileBuf = qalloc(nFileSize);
	if (!lpFileBuf)
	{
		ASSERT(lpFileBuf);
		return nullptr;
	}
	FILE* f = qfopen(pszFileName, pszMode);
	if (!f)
	{
		ASSERT(f);
		return nullptr;
	}
	nFileSize = qfread(f, lpFileBuf, sizeof(uchar) * nFileSize);
	qfclose(f);

	qstring result((const char*)lpFileBuf, nFileSize);
	qfree(lpFileBuf);
	lpFileBuf = nullptr;
	return result;
}

//此函数来自https://stackoverflow.com/questions/14374272/how-to-parse-version-number-to-compare-it
/*
 * return 1 if v1 > v2
 * return 0 if v1 = v2
 * return -1 if v1 < v2
 */
static int CompareFileVersion(const wchar_t* v1, const wchar_t* v2)
{
	int i;
	int oct_v1[4], oct_v2[4];
	int ret1 = swscanf(v1, L"%d.%d.%d.%d", &oct_v1[0], &oct_v1[1], &oct_v1[2], &oct_v1[3]);
	int ret2 = swscanf(v2, L"%d.%d.%d.%d", &oct_v2[0], &oct_v2[1], &oct_v2[2], &oct_v2[3]);
	ASSERT(ret1 == 4 && ret2 == 4);
	if (ret1 != 4 || ret2 != 4)
	{
		return wcscmp(v1, v2);
	}

	for (i = 0; i < 4; i++)
	{
		if (oct_v1[i] > oct_v2[i])
			return 1;
		else if (oct_v1[i] < oct_v2[i])
			return -1;
	}

	return 0;
}