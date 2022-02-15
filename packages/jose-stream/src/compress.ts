import {
  BrotliCompress,
  BrotliDecompress,
  BrotliOptions,
  createBrotliCompress,
  createBrotliDecompress,
  createDeflate,
  createGunzip,
  createGzip,
  createInflate,
  Deflate,
  Gunzip,
  Gzip,
  Inflate,
  ZlibOptions
} from 'zlib'

export function createCompress(
  type: string,
  options: ZlibOptions | BrotliOptions | undefined
): Gzip | Deflate | BrotliCompress {
  switch (type.toLowerCase()) {
    case 'gz':
    case 'gzip':
      return createGzip(options)
    case 'def':
    case 'deflate':
      return createDeflate(options)
    case 'br':
      return createBrotliCompress(options)
    default:
      throw new Error(`unknown compression type '${type}'`)
  }
}

export function createDecompress(
  type: string
): Gunzip | Inflate | BrotliDecompress {
  switch (type.toLowerCase()) {
    case 'gz':
    case 'gzip':
      return createGunzip()
    case 'def':
    case 'deflate':
      return createInflate()
    case 'br':
      return createBrotliDecompress()
    default:
      throw new Error(`unknown compression type '${type}'`)
  }
}
