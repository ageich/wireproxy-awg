package wireproxy

import (
	"io"
	"sync"
)

const defaultBufferSize = 64 * 1024 // 64KB подходит для TCP и UDP

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, defaultBufferSize)
	},
}

// GetBuffer возвращает буфер из пула
func GetBuffer() []byte {
	return bufferPool.Get().([]byte)
}

// PutBuffer возвращает буфер обратно в пул
func PutBuffer(buf []byte) {
	if cap(buf) >= defaultBufferSize {
		bufferPool.Put(buf[:cap(buf)])
	}
	// Если буфер меньше, не возвращаем (или можно вернуть, но мы всегда используем одинаковый размер)
}

// CopyWithPool копирует данные из src в dst, используя буфер из пула
func CopyWithPool(dst io.Writer, src io.Reader) (int64, error) {
	buf := GetBuffer()
	defer PutBuffer(buf)
	return io.CopyBuffer(dst, src, buf)
}
