package wireproxy

import (
	"io"
	"sync"
)

const defaultBufferSize = 64 * 1024 // 64KB

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
// Буфер обрезается до defaultBufferSize, чтобы избежать удержания больших ёмкостей.
func PutBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// Обрезаем буфер до defaultBufferSize, если он больше
	if cap(buf) > defaultBufferSize {
		bufferPool.Put(buf[:defaultBufferSize])
	} else {
		bufferPool.Put(buf[:cap(buf)])
	}
}

// CopyWithPool копирует данные из src в dst, используя буфер из пула
func CopyWithPool(dst io.Writer, src io.Reader) (int64, error) {
	buf := GetBuffer()
	defer PutBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}
