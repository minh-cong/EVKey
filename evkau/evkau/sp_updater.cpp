#include "stdafx.h"
#include "sp_updater.h"
#include <vector>
#include <iterator>  
#include <list>  
#include "c_download_dlg.h"
#include <string>
#include <experimental/filesystem>

#if USE_CURL
#include "curl.h"
#endif

#include <winhttp.h>
#pragma comment(lib, "winhttp.lib") 

#pragma comment(lib, "version.lib") 

#define MAIN_WINDOW_CLASS_NAME L"EVKey_MainWnd"
#define WM_MYICON_NOTIFY					(WM_USER + 1)
#define WM_CMD_FROM_OTHER_PROCESS (WM_USER + 2)
#define MESSAGE_CLOSE_EVKEY        1000

#define _WIN32_WINNT_WIN81                0x0603

namespace fs = std::experimental::filesystem;

const wchar_t*	g_server_evkey = L"raw.githubusercontent.com";
const char*			g_link_release = "https://raw.githubusercontent.com/lamquangminh/EVKey/master/release/";


#define _WIN32_WINNT_NT4      0x0400
#define _WIN32_WINNT_WIN2K    0x0500
#define _WIN32_WINNT_WINXP    0x0501
#define _WIN32_WINNT_WS03     0x0502
#define _WIN32_WINNT_WIN6     0x0600
#define _WIN32_WINNT_VISTA    0x0600
#define _WIN32_WINNT_WS08     0x0600
#define _WIN32_WINNT_LONGHORN 0x0600
#define _WIN32_WINNT_WIN7     0x0601
#define _WIN32_WINNT_WIN8     0x0602
#define _WIN32_WINNT_WINBLUE  0x0603
#define _WIN32_WINNT_WIN10    0x0A00


typedef wnd_bool(__stdcall *pVerifyVersionInfo)(LPOSVERSIONINFOEX lpVersionInfo, DWORD dwTypeMask, DWORDLONG dwlConditionMask);
typedef ULONGLONG(__stdcall *pVerSetConditionMask)(__in ULONGLONG ConditionMask,__in DWORD TypeMask,__in BYTE  Condition);

BOOL IsWinVersionOrGreater(DWORD id, WORD wServicePackMajor)
{
	WORD wMajorVersion = HIBYTE(id);
	WORD wMinorVersion = LOBYTE(id);

	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0 };

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	HMODULE hMod = ::LoadLibrary(L"kernel32.dll");
	if (hMod) {

		pVerSetConditionMask funcVerSet = (pVerSetConditionMask)::GetProcAddress(hMod, "VerSetConditionMask");
		DWORDLONG dwlConditionMask = 0;
		if(funcVerSet)
			dwlConditionMask = funcVerSet( funcVerSet( funcVerSet(0, VER_MAJORVERSION, VER_GREATER_EQUAL),	VER_MINORVERSION, VER_GREATER_EQUAL),
				VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

		pVerifyVersionInfo funcVersion = (pVerifyVersionInfo)::GetProcAddress(hMod, "VerifyVersionInfoW");
		if (funcVersion)
			return funcVersion(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
	}
	return FALSE;
}

BOOL __stdcall IsWindowsXPOrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WINXP, 0); }
BOOL __stdcall IsWindowsXPSP1OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WINXP, 1); }
BOOL __stdcall IsWindowsXPSP2OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WINXP, 2); }
BOOL __stdcall IsWindowsXPSP3OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WINXP, 3); }
BOOL __stdcall IsWindowsVistaOrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_VISTA, 0); }
BOOL __stdcall IsWindowsVistaSP1OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_VISTA, 1); }
BOOL __stdcall IsWindowsVistaSP2OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_VISTA, 2); }
BOOL __stdcall IsWindows7OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WIN7, 0); }
BOOL __stdcall IsWindows7SP1OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WIN7, 1); }
BOOL __stdcall IsWindows8OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WIN8, 0); }
BOOL __stdcall IsWindows8Point1OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WINBLUE, 0); }
BOOL __stdcall IsWindows10OrGreater() { return IsWinVersionOrGreater(_WIN32_WINNT_WIN10, 0); }

typedef BOOL (__stdcall *pIsWindows8Point1OrGreater)(void);

BOOL IsWindows81OrGreater()
{
	pIsWindows8Point1OrGreater funcVerSet = nullptr;

	HMODULE hMod = ::LoadLibrary(L"kernel32.dll");
	if (hMod)
		funcVerSet = (pIsWindows8Point1OrGreater)::GetProcAddress(hMod, "IsWindows8Point1OrGreater");

	if (!funcVerSet)
	{
		HMODULE hMod = ::LoadLibrary(L"ntdll.dll");
		if (hMod)
			funcVerSet = (pIsWindows8Point1OrGreater)::GetProcAddress(hMod, "IsWindows8Point1OrGreater");
	}

	if (!funcVerSet)
		funcVerSet = IsWindows8Point1OrGreater;

	return funcVerSet();
}

bool is_elevated()
{
	bool fRet = false;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
		{
			fRet = Elevation.TokenIsElevated != 0;
		}
	}

	if (hToken)
	{
		CloseHandle(hToken);
	}

	return fRet;
}

inline stdwstring string2wstring(const stdstring str) {
	return stdwstring(str.begin(), str.end());
}

void split_wstring(const wchar_t* str, const wchar_t token, c_wstring_buffer& ctn)
{
        if (!str || *str == L'\0')
                return;

        std::wstring temp(str);
        std::wstring strtoken(1, token);
        wchar_t *next_token = fl_null;

        // Use a mutable copy to preserve 'temp' and avoid casting away const.
        std::wstring mutable_copy = temp;
        wchar_t* buffer = &mutable_copy[0];
        wchar_t* pch = wcstok_s(buffer, strtoken.c_str(), &next_token);
        while (pch != nullptr)
        {
                ctn.push_back(pch);
                pch = wcstok_s(nullptr, strtoken.c_str(), &next_token);
        }
}

stdwstring exe_full_path()
{
	wchar_t buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, MAX_PATH);
	return stdwstring(buffer);
}

stdwstring exe_path()
{
	auto parent_path = fs::path(exe_full_path());
	return stdwstring(parent_path.parent_path().c_str());
}

stdwstring get_evkey_full_path(int flatform)
{
	return exe_path() + L"\\EVKey" + std::to_wstring(flatform) + L".exe";
}

int GetVersionEVkey(int flatform)
{
	stdwstring file_name = get_evkey_full_path(flatform);
	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSizeW(file_name.c_str(), &verHandle);

	if (verSize != NULL)
	{
		c_char_buffer verData(verSize);

		if (GetFileVersionInfoW(file_name.c_str(), verHandle, verSize, verData.data()))
		{
			if (VerQueryValueW(verData.data(), L"\\", (VOID FAR* FAR*)&lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO *verInfo = (VS_FIXEDFILEINFO *)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						int l = (verInfo->dwFileVersionMS >> 16) & 0xffff;
						int m = (verInfo->dwFileVersionMS >> 0) & 0xffff;
						int s = (verInfo->dwFileVersionLS >> 16) & 0xffff;

						return l * 100 + m * 10 + s;
					}
				}
			}
		}
	}

	return 0;
}

bool run_evkey_process(int flatform, wnd_bool is_portable)
{
	auto exe_full_path = get_evkey_full_path(flatform);

	stdwstring arg = L"-r";
	if (is_portable)
		arg.append(L" -p");

	arg.append(L" -s");

	wchar_t* run_type = nullptr;

	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

	STARTUPINFOW startup;
	::ZeroMemory(&startup, sizeof(startup));
	startup.cb = sizeof(startup);

	startup.dwFlags = STARTF_USESTDHANDLES;

	PROCESS_INFORMATION procInfo;
	memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));

	int64 ret = (int64)::ShellExecuteW(NULL,
		run_type,
		(LPWSTR)(LPCWSTR)exe_full_path.c_str(),
		arg.c_str(),
		NULL,
		SW_SHOWNORMAL);

	return (ret > 32);
}

struct download_response_data_t {
	data_response_t* data;
	int							 current_size;
};

static size_t curl_write_call_back(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	download_response_data_t* data_response = (download_response_data_t *)userp;

	c_char_buffer& buff = (data_response->data->buffer_cache);

	buff.insert(buff.end(), (char*)contents, ((char*)contents) + realsize);

	if (data_response->data->res_hwnd)
		SendMessage(data_response->data->res_hwnd, MSG_PROGRESS_DOWNLOAD, data_response->current_size, (LPARAM)buff.size());

	//Sleep(1000);

	return realsize;
}

BOOL CreateRequestSession(const stdwstring& strlink, HINTERNET& hSession, HINTERNET& hConnect, HINTERNET& hRequest)
{
	BOOL  bResults = FALSE;
	hSession = NULL;
	hConnect = NULL;
	hRequest = NULL;

  URL_COMPONENTS urlComponents{};
  urlComponents.dwStructSize = sizeof(urlComponents);
  urlComponents.dwSchemeLength = static_cast<DWORD>(-1);
  urlComponents.dwHostNameLength = static_cast<DWORD>(-1);
  urlComponents.dwUrlPathLength = static_cast<DWORD>(-1);
  const BOOL bSuccess = WinHttpCrackUrl(strlink.c_str(), 0, 0, &urlComponents);
  if (!bSuccess)
  {
    return FALSE;
  }
	
	// Use WinHttpOpen to obtain a session handle.

  if (IsWindows81OrGreater())
  {
    hSession = WinHttpOpen(L"EVKeyUpdater",
      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
      WINHTTP_NO_PROXY_NAME,
      WINHTTP_NO_PROXY_BYPASS, 0);
  }
  else
  {
		hSession = WinHttpOpen(L"EVKeyUpdater",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);
	}

	WinHttpSetTimeouts(hSession, 10000, 10000, 10000, 10000);

	if (hSession)
	{
		stdwstring host_name(urlComponents.lpszHostName, urlComponents.dwHostNameLength);
		hConnect = WinHttpConnect(hSession, host_name.c_str(),
			INTERNET_DEFAULT_HTTPS_PORT, 0);
	}

	const wchar_t* fileType[] = { L"*/*", 0 };
	if (hConnect)
	{
		stdwstring file_name(urlComponents.lpszUrlPath, urlComponents.dwUrlPathLength);
		hRequest = WinHttpOpenRequest(hConnect, L"", file_name.c_str(), 
			NULL, WINHTTP_NO_REFERER,
			(LPCWSTR*)fileType,
			WINHTTP_FLAG_SECURE);
	}

  //DWORD dwTmp = SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA;
  //WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&dwTmp, sizeof(dwTmp));

	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS,
			0, WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);

	return bResults;
}

bool get_file_size(const char* sRequest, int& size)
{
#if USE_CURL
	bool ret = true;
	curl_global_init(CURL_GLOBAL_ALL);
	CURL *curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, sRequest);

		char error_buffer[CURL_ERROR_SIZE] = {};
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_HEADER, 1);
		curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

		if (!curl_easy_perform(curl)) {
			curl_off_t cl;
			CURLcode res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &cl);
			if (!res) {
				size = (int)cl;
				ret = true;
			}
			else
				ret = false;
		}
		else
			ret = false;

		curl_easy_cleanup(curl);
	}

	return ret;
#else
	bool ret = false;
	DWORD dwSize = 0;
	
	HINTERNET hSession, hConnect, hRequest;

	stdwstring strlink = string2wstring(sRequest);
	
	if (CreateRequestSession(strlink, hSession, hConnect, hRequest))
	{
		if (WinHttpReceiveResponse(hRequest, NULL))
		{
			DWORD _len = 0xdeadbeef;
			DWORD _size = sizeof(_len);
			if (WinHttpQueryHeaders(hRequest, 5 | 0x20000000,
				NULL, &_len, &_size, NULL))
			{
				size = _len;
				ret = true;
			}
		}
	}

	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);

	return ret;
#endif
}

namespace sp_updater
{
	BOOL send_request(const char* sRequest, data_response_t& sResponse)
	{
		sResponse.buffer_cache.resize(0);
#if USE_CURL
		curl_global_init(CURL_GLOBAL_ALL);
		CURL * curl = curl_easy_init();
		BOOL ret = FALSE;
		if (curl)
		{
			int size;
			if (get_file_size(sRequest, size))
			{
				download_response_data_t rdata = { &sResponse, (int)size };

				curl_easy_setopt(curl, CURLOPT_URL, sRequest);

				char error_buffer[CURL_ERROR_SIZE] = {};
				curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

				curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_write_call_back);


				curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
				curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
				//curl_easy_setopt(curl, CURLOPT_CAINFO, "cacert.pem");

				curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rdata);
				curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

				ret = curl_easy_perform(curl) == CURLcode::CURLE_OK;
			}
			curl_easy_cleanup(curl);
		}
#else
		BOOL ret = 1;
		int file_zize;
		if (get_file_size(sRequest, file_zize))
		{
			DWORD dwSize = 0;
			DWORD dwDownloaded = 0;
			
			HINTERNET hSession, hConnect, hRequest;

			stdwstring strlink = string2wstring(sRequest);

			if (CreateRequestSession(strlink, hSession, hConnect, hRequest))
			{
				if (WinHttpReceiveResponse(hRequest, NULL))
				{
					do
					{
						// Check for available data.
						dwSize = 0;
						if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
							ret = 0;
							break;
						}

						if (dwSize == 0)
							break;

						// Allocate space for the buffer.
						c_char_buffer buffer(dwSize + 1);
						ZeroMemory(buffer.data(), dwSize + 1);

						if (!WinHttpReadData(hRequest, (LPVOID)buffer.data(), dwSize, &dwDownloaded))
						{
							ret = 0;
							break;
						}

						if (_strnicmp(buffer.data(), "404: not found", 14) == 0)
						{
							ret = 0;
							break;
						}

						sResponse.buffer_cache.insert(sResponse.buffer_cache.end(), buffer.data(), buffer.data() + dwSize);

						if (sResponse.res_hwnd)
							SendMessage(sResponse.res_hwnd, MSG_PROGRESS_DOWNLOAD, file_zize, (LPARAM)sResponse.buffer_cache.size());

					} while (dwSize > 0);
				}
				else {
					ret = 0;
				}
			}
			else {
				ret = 0;
			}

			if (hRequest) WinHttpCloseHandle(hRequest);
			if (hConnect) WinHttpCloseHandle(hConnect);
			if (hSession) WinHttpCloseHandle(hSession);
		}
		else {
			ret = 0;
		}

#endif

		if (sResponse.res_hwnd)
		{
			if (ret)
				SendMessage(sResponse.res_hwnd, MSG_PROGRESS_DOWNLOAD, 100, 100);
			else
				SendMessage(sResponse.res_hwnd, MSG_PROGRESS_DOWNLOAD, -1, 0);
		}

		return ret;
	}

	int close_evkey()
	{
		int ret = 0;
		HWND hPrevWnd;
		while ((hPrevWnd = FindWindowW(MAIN_WINDOW_CLASS_NAME, NULL)))
		{
			//force SendMessage, not PostMessage
			SendMessage(hPrevWnd, WM_CMD_FROM_OTHER_PROCESS, MESSAGE_CLOSE_EVKEY, 0);
			Sleep(100);

			ret = 1;
		}
		return ret;
	}

	BOOL Is64BitOS()
	{
		BOOL bIs64Bit = FALSE;

		typedef BOOL(WINAPI *LPFNISWOW64PROCESS) (HANDLE, PBOOL);
		LPFNISWOW64PROCESS pfnIsWow64Process = (LPFNISWOW64PROCESS)GetProcAddress(GetModuleHandle(L"kernel32"), "IsWow64Process");

		if (pfnIsWow64Process)
			pfnIsWow64Process(GetCurrentProcess(), &bIs64Bit);

		return bIs64Bit;
	}

	int process_command(LPWSTR lpCmdLine, int& out_version, int& out_flat_form, int& is_portable, int& is_silence)
	{
		//MessageBoxW(NULL, lpCmdLine, L"Command", MB_OK);

		int current_flatform = 0, current_version = 0;
		is_portable = 0, is_silence = 0;

		if (lpCmdLine && wcslen(lpCmdLine))
		{
			c_wstring_buffer cmds;
			split_wstring(lpCmdLine, L' ', cmds);

			for (int i = 0; i < (int)cmds.size(); ++i)
			{
				if (cmds[i] == L"-p") {
					is_portable = 1;
				}
				else if (cmds[i] == L"-s") {
					is_silence = 1;
				}
				else
				{
					stdwstring cmd;
					cmd += cmds[i][0];
					if (cmds[i].size() > 1)
						cmd += cmds[i][1];

					if (cmd == L"-f") {
						current_flatform = _wtoi(&cmds[i][2]);
					}
					else if (cmd == L"-v") {
						current_version = _wtoi(&cmds[i][2]);
					}
				}
			}

			if (current_flatform != 32 && current_flatform != 64)
				return error_command;

			if (current_version < 100 || current_version > 900)
				return error_command;

			out_flat_form = current_flatform;
		}
		else
		{
			if (sizeof(char*) == 8)
				out_flat_form = 64;
			else if (Is64BitOS())
				out_flat_form = 64;
			else
				out_flat_form = 32;

			current_version = GetVersionEVkey(out_flat_form);
		}

		data_response_t data;

		std::string link = std::string(g_link_release) + "cversion.txt";
		if (send_request(link.c_str(), data))
		{
			std::string str_new_version(data.buffer_cache.begin(), data.buffer_cache.end());
			out_version = atoi(str_new_version.c_str());

			if (out_version > current_version)
				return out_version;
			else
				return error_noerror;
		}
		else
			return error_connection;

		return error_command;
	}

	int check_write_file()
	{
		stdwstring fname = exe_path() + L"\\evkau.tst";
		FILE* file = NULL;
		errno_t ret = _wfopen_s(&file, fname.c_str(), L"wb");

		if (ret != 0 || file == NULL)
			return 0;
		
		fclose(file);

		DeleteFile(fname.c_str());

		return 1;
	}

	int action(HINSTANCE hins, HWND main_hwnd, LPWSTR lpCmdLine)
  	{
#if !USE_STATIC_LIB
		initNetwork();
#endif

		int version, flatform, is_portable, is_silence;
		int ret = process_command(lpCmdLine, version, flatform, is_portable, is_silence);

		if (ret > error_noerror)
		{
			int l = (version / 100);
			int m = (version / 10) % 10;
			int s = version % 10;
			stdwstring strversion = std::to_wstring(l) + L"." + std::to_wstring(m) + L"." + std::to_wstring(s);
			stdwstring strinform = L"EVKey" + std::to_wstring(flatform) + L" có version " + strversion + L" mới. Bạn có muốn cập nhật không ?";

			if (MessageBox(main_hwnd, strinform.c_str(), L"EVKey - Auto update", MB_YESNO | MB_ICONINFORMATION) == IDYES)
			{
				if (!check_write_file())
				{
					MessageBox(main_hwnd, L"EVkey không thể ghi dữ liệu ở vị trí hiện tại, vui lòng chuyển EVKey vào nơi có quyền ghi, hoặc khởi động lại EVKey với quyền Administrator.", L"EVKey - Auto update", MB_OK);
					ret = error_is_not_elevated;
				}
				else
				{
					std::string file_name = "EVKey" + std::to_string(flatform) + ".exe";
					std::string link = std::string(g_link_release) + file_name;
					c_download_dlg dlg(link, hins, main_hwnd);
					dlg.show_dialog();
					if (dlg.m_result == 1)
					{
						if (dlg.m_downloaded_size == dlg.m_data_size)
						{
							stdwstring fname = exe_path() + L"\\EVKey" + std::to_wstring(flatform) + L".exe";

							MessageBox(main_hwnd, L"Tải thành công. Nhấn Ok để cập nhật", L"EVKey - Auto update", MB_ICONINFORMATION);

							int is_close = close_evkey();
							Sleep(1000);
							close_evkey();

							FILE* file;
							_wfopen_s(&file, fname.c_str(), L"wb");
							if (file)
							{
								size_t size = fwrite(dlg.m_down_data.buffer_cache.data(),
									(std::size_t)dlg.m_down_data.buffer_cache.size(),
									1, file);

								if (size != 1 && !is_silence)
									MessageBoxW(NULL, L"Không thể ghi file. Vui lòng kiểm tra lại.", L"EVKey - Auto update", MB_ICONERROR);

								fclose(file);
							}
							else
							{
								if (!is_silence)
									MessageBoxW(NULL, L"Không thể ghi file. Vui lòng kiểm tra lại.", L"EVKey - Auto update", MB_ICONERROR);
							}

							if (is_close) {
								run_evkey_process(flatform, is_portable);
							}

							ret = error_download_success;
						}
						else
						{
							ret = error_connection;
						}
					}
				}
			}
		}

		switch (ret)
		{
		case error_noerror:
		{
			if (!is_silence)
				MessageBoxW(NULL, L"Phiên bản đang sử dụng là mới nhất.", L"EVKey - Auto update", MB_ICONINFORMATION);
		}
		break;

		case error_connection:
		{
			if (!is_silence)
				MessageBoxW(NULL, L"Đã xảy ra lỗi trong quá trình kết nối.", L"EVKey - Auto update", MB_ICONERROR);
		}
		break;

		case error_command:
		{
			if (!is_silence)
				MessageBoxW(NULL, L"Có lỗi trong quá trình thực thi.", L"EVKey - Auto update", MB_ICONERROR);
		}
		break;

		default:
			break;
		}

		DETROY_WINDOW(main_hwnd);

		return ret;
	}
}
