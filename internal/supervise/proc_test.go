package supervise

import (
	"testing"
)

func TestPidLifecycle(t *testing.T) {
	if _, alive := Alive(); alive {
		t.Skip("pid file busy (сервер запущен?)")
	}
	// тестируем только Tail на отсутствующем логе и Status down.
	if st, _ := Status("http://127.0.0.1:1"); st != "down" {
		t.Fatalf("status: %s", st)
	}
	if got := Tail(5); got == "" {
		t.Fatal("tail empty")
	}
	if err := Stop(); err == nil {
		t.Fatal("stop without pid must fail")
	}
	// круговой тест Start/Stop на текущем бинарнике невозможен без сервера —
	// проверяем старт несуществующего exe
	if _, err := Start("phantom-no-such-exe-12345", nil); err == nil {
		t.Fatal("bad exe must fail")
	}
}
