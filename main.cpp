#include "func.h"

// �������� ������� ��������� ���������

ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

// ������� ��������
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR
	lpCmdLine,
	int nCmdShow)
{
	MSG msg;
	// ��������� ����� ����
	MyRegisterClass(hInstance);
	// ��������� ���� ��������
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}
	// ���� ������� ����������
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return msg.wParam;

}
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style = CS_HREDRAW | CS_VREDRAW; //����� ����
	wcex.lpfnWndProc = (WNDPROC)WndProc; //������ ���������
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance; //���������� ��������
	wcex.hIcon = LoadIcon(NULL, IDI_INFORMATION); //���������� ������
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW); //���������� �������
	wcex.hbrBackground = GetSysColorBrush(COLOR_WINDOW); //��������� ����
	wcex.lpszMenuName = NULL; //���������� ����
	wcex.lpszClassName = szWindowClass; //��� �����
	wcex.hIconSm = NULL;
	return RegisterClassEx(&wcex); //��������� ����� ����
}
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	HWND hWnd;
	hInst = hInstance; //������ ���������� ������� � ����� hInst
	hWnd = CreateWindow(szWindowClass, // ��� ����� ����
		szTitle, // ����� ��������
		WS_OVERLAPPEDWINDOW, // ����� ����
		CW_USEDEFAULT, // ��������� �� �
		CW_USEDEFAULT, // ��������� �� Y
		900, // ����� �� �
		600, // ����� �� Y
		NULL, // ���������� ������������ ����
		NULL, // ���������� ���� ����
		hInstance, // ���������� ��������
		NULL); // ��������� ���������.
	if (!hWnd) //���� ���� �� ���������, ������� ������� FALSE
	{
		return FALSE;
	}
	ShowWindow(hWnd, nCmdShow); //�������� ����
	UpdateWindow(hWnd); //������� ����
	return TRUE;
}


// ������� ��������� ���������
LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
		hLog = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER |
			ES_MULTILINE | WS_VSCROLL, 350, 80, 500, 370, hwnd, nullptr, nullptr, nullptr);
		hStartSniffer = CreateWindow("BUTTON", "Start Sniffer", WS_VISIBLE | WS_CHILD, 80,
			70, 150, 40, hwnd, (HMENU)1, nullptr, nullptr);
		hStopSniffer = CreateWindow("BUTTON", "Stop Sniffer", WS_VISIBLE | WS_CHILD, 80,
			120, 150, 40, hwnd, (HMENU)2, nullptr, nullptr);
		CreateWindow("STATIC", "-------------------------Add Rule-------------------------", WS_VISIBLE | WS_CHILD, 30,
			180 ,260, 20, hwnd, nullptr, nullptr, nullptr);
		CreateWindow("STATIC", "IP - ", WS_VISIBLE | WS_CHILD, 20,
			220, 30, 20, hwnd, nullptr, nullptr, nullptr);
		hAddRuleInput = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 50,
			220, 210, 20, hwnd, nullptr, nullptr, nullptr);
		hAddRule = CreateWindow("BUTTON", "Add Rule", WS_VISIBLE | WS_CHILD, 100,
			250, 100, 30, hwnd, (HMENU)3, nullptr, nullptr);
		CreateWindow("STATIC", "-------------------------Del Rule-------------------------", WS_VISIBLE | WS_CHILD, 30,
			300, 260, 20, hwnd, nullptr, nullptr, nullptr);
		CreateWindow("STATIC", "IP - ", WS_VISIBLE | WS_CHILD, 20,
			340, 30, 20, hwnd, nullptr, nullptr, nullptr);
		hDelRuleInput = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER, 50,
			340, 210, 20, hwnd, nullptr, nullptr, nullptr);
		hDelRule = CreateWindow("BUTTON", "Del Rule", WS_VISIBLE | WS_CHILD, 100,
			370, 100, 30, hwnd, (HMENU)4, nullptr, nullptr);
		CreateWindow("STATIC", "------------------------------------------------------------------", WS_VISIBLE | WS_CHILD, 30,
			420, 260, 20, hwnd, nullptr, nullptr, nullptr);
		hViewRule = CreateWindow("BUTTON", "View Rule", WS_VISIBLE | WS_CHILD, 100,
			460, 100, 30, hwnd, (HMENU)5, nullptr, nullptr);

		InitDriver();
		checkiFile();
        break;
    }
	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case 1: { // Start Sniffer
			if (!is_Sniffing) {
				AddLog("Starting sniffer...\n");
				startSnifferThread(list_device()[5]);
			}
			else {
				AddLog("Sniffer already running.\n");
			}
			break;
		}
		case 2: { // Stop Sniffer
			stopSnifferThread();
			break;
		}
		case 3: { // Stop Sniffer
			char buffer[256]; 
			GetWindowText(hAddRuleInput, buffer, sizeof(buffer)); 
			std::string rule(buffer);
			addRuleFile(rule);

			SetWindowText(hAddRuleInput, "");
			break;
		}
		case 4: { // Stop Sniffer
			char buffer[256]; 
			GetWindowText(hDelRuleInput, buffer, sizeof(buffer)); 
			std::string rule(buffer);
			if (removeRuleFromFile(rule)) {
				SetWindowText(hDelRuleInput, "");
			}
			break;
		}
		case 5: { // Rule
			viewRuleFile();
		break;
		}
		}
		break;
	}
    case WM_DESTROY:
        PostQuitMessage(0);  
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        FillRect(hdc, &ps.rcPaint, (HBRUSH)(COLOR_WINDOW + 1));  
        EndPaint(hwnd, &ps);
    }
    return 0;
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}
