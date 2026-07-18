package wireproxy

import (
	"io"
	"sync"
)

const (
	defaultBufferSize = 64 * 1024 // 64KB
	maxBufferCap      = 4096      // максимальный разумный размер буфера для возврата в пул
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, defaultBufferSize)
	},
}

// GetBuffer возвращает буфер из пула
func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// PutBuffer возвращает буфер обратно в пул.
// Если ёмкость буфера превышает maxBufferCap (4096 байт), буфер не возвращается в пул,
// чтобы GC мог его удалить и освободить память.
// Также проверяется, что буфер не nil.
func PutBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// Если ёмкость превышает лимит — не возвращаем в пул
	if cap(buf) > maxBufferCap {
		return
	}
	// Если буфер меньше defaultBufferSize, создаём новый
	if cap(buf) < defaultBufferSize {
		bufferPool.Put(make([]byte, defaultBufferSize))
		return
	}
	// Возвращаем буфер в пул (обрезаем до defaultBufferSize)
	bufferPool.Put(buf[:defaultBufferSize])
}

// CopyWithPool копирует данные из src в dst, используя буфер из пула
func CopyWithPool(dst io.Writer, src io.Reader) (int64, error) {
	buf := GetBuffer()
	defer PutBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}
