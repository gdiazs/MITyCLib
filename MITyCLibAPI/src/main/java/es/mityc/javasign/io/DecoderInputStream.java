/**
 * Copyright 2013 Ministerio de Industria, Energía y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
 *
 * Licencia con arreglo a la EUPL, Versión 1.1 o –en cuanto sean aprobadas por la Comisión Europea– versiones posteriores de la EUPL (la Licencia);
 * Solo podrá usarse esta obra si se respeta la Licencia.
 *
 * Puede obtenerse una copia de la Licencia en:
 *
 * http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
 *
 * Salvo cuando lo exija la legislación aplicable o se acuerde por escrito, el programa distribuido con arreglo a la Licencia se distribuye «TAL CUAL»,
 * SIN GARANTÍAS NI CONDICIONES DE NINGÚN TIPO, ni expresas ni implícitas.
 * Véase la Licencia en el idioma concreto que rige los permisos y limitaciones que establece la Licencia.
 */
package es.mityc.javasign.io;

import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * <p>Implementación de {@link FilterInputStream} que permite filtrar los datos de entrada mediante un decodificador que implemente el interfaz
 * {@link IDecoder}.</p>
 * 
 * <p>Basado en el <i>stream</i> {@link java.util.zip.InflaterInputStream}, adaptado para permitir una forma más general de decodificación.</p>
 * 
 */
public class DecoderInputStream extends FilterInputStream {
	
	/** Número máximo de intentos de rellenar el buffer con nuevos datos. */
	private static final int MAX_TRIES = 3;
	/** Tamaño por defecto del buffer interno. */
	private static final int DEFAULT_BUFFER_SIZE = 512;
	
	/** Decodificador asociado al <i>stream</i>. */
	protected IDecoder decoder;
	/** Input buffer for decompression. */
    protected byte[] buf;
    /** Length of input buffer. */
    protected int lenBuffer;
    /** Flag que indica si el stream de lectura está cerrado.*/
    private boolean closed = false;
    /** this flag is set to true after EOF has reached. */
    private boolean reachEOF = false;


	/**
	 * <p>Constructor.</p>
	 * @param in InputStream desde donde se leerán los datos codificados
	 * @param dec Decodificador que se utilizará para convertir los datos
	 */
    public DecoderInputStream(InputStream in, IDecoder dec) {
		this(in, dec, DEFAULT_BUFFER_SIZE);
	}

	/**
	 * <p>Constructor.</p>
	 * @param in InputStream desde donde se leerán los datos codificados
	 * @param dec Decodificador que se utilizará para convertir los datos
	 * @param size Tamaño del buffer interno de lectura que se le pasará al decodificador
	 */
    public DecoderInputStream(InputStream in, IDecoder dec, final int size) {
		super(in);
        if (in == null || dec == null) {
            throw new NullPointerException();
        } else if (size <= 0) {
            throw new IllegalArgumentException("buffer size <= 0");
        }
		this.decoder = dec;
		buf = new byte[size];
	}
	
    /**
     * <p>Check to make sure that this stream has not been closed.</p>
     * @throws IOException launched with Stream closed
     */
    private void ensureOpen() throws IOException {
		if (closed) {
		    throw new IOException("Stream closed");
        }
    }

    /** Buffer para leer un único byte. */
    private byte[] singleByteBuf = new byte[1];
    /** Máscara para convertir un byte en int. */
    private static final int MASK_BYTE = 0xff;

    /**
     * Reads a byte of uncompressed data. This method will block until
     * enough input is available for decompression.
     * @return the byte read, or -1 if end of compressed input is reached
     * @exception IOException if an I/O error has occurred
     */
    public int read() throws IOException {
		ensureOpen();
		return read(singleByteBuf, 0, 1) == -1 ? -1 : singleByteBuf[0] & MASK_BYTE;
    }

    /**
     * Reads encoded data into an array of bytes. This method will
     * block until some input can be decoded.
     * @param b the buffer into which the data is read
     * @param off the start offset of the data
     * @param len the maximum number of bytes read
     * @return the actual number of bytes read, or -1 if the end of the
     *         encoded input is reached
     * @exception IOException if an I/O error has occurred
     * <ul>
     * 	<li>{@link DecodingException} if a encoding format error has occurred</li>
     * </ul>
     */
    public int read(byte[] b, final int off, final int len) throws IOException {
    	ensureOpen();
        if ((off | len | (off + len) | (b.length - (off + len))) < 0) {
		    throw new IndexOutOfBoundsException();
		} else if (len == 0) {
		    return 0;
		}
	    int n;
	    int tries = 0;
	    while ((n = decoder.decode(b, off, len)) == 0) {
			if (decoder.needsInput()) {
			    if (fill() == -1) {
			    	if (decoder.isIncomplete()) {
			    		throw new EOFException("Decoder has buffer not depleted");
			    	}
	                reachEOF = true;
			    	return -1;
			    }
			}
			tries++;
			if (tries > MAX_TRIES) {
				break;
			}
	    }
	    return n;
    }

    /**
     * Returns 0 after EOF has been reached, otherwise always return 1.
     * <p>
     * Programs should not count on this method to return the actual number
     * of bytes that could be read without blocking.
     *
     * @return     1 before EOF and 0 after EOF.
     * @exception  IOException  if an I/O error occurs.
     * 
     */
    public int available() throws IOException {
        ensureOpen();
        if (reachEOF) {
            return 0;
        } else {
            return 1;
        }
    }

    /** buffer interno para calcular el skip. */
    private byte[] tempBuffer = new byte[DEFAULT_BUFFER_SIZE];

    /**
     * <p>Skips specified number of bytes of decoded data.</p>
     * <p>Could throw {@link IllegalArgumentException} if n &lt; 0.</p>
     * @param n the number of bytes to skip
     * @return the actual number of bytes skipped.
     * @exception IOException if an I/O error has occurred
     */
    public long skip(final long n) throws IOException {
        if (n < 0) {
            throw new IllegalArgumentException("negative skip length");
        }
		ensureOpen();
		int max = (int) Math.min(n, Integer.MAX_VALUE);
		int total = 0;
		while (total < max) {
		    int len = max - total;
		    if (len > tempBuffer.length) {
		    	len = tempBuffer.length;
		    }
		    len = read(tempBuffer, 0, len);
		    if (len == -1) {
                reachEOF = true;
                break;
		    }
		    total += len;
		}
		return total;
    }

    /**
     * Closes this input stream and releases any system resources associated
     * with the stream.
     * @exception IOException if an I/O error has occurred
     */
    public void close() throws IOException {
        if (!closed) {
        	in.close();
            closed = true;
        }
    }

    /**
     * Fills input buffer with more data to decoded.
     * @return bytes filled
     * @exception IOException if an I/O error has occurred
     */
    protected int fill() throws IOException {
		ensureOpen();
		lenBuffer = in.read(buf, 0, buf.length);
		if (lenBuffer > -1) {
			decoder.addInput(buf, 0, lenBuffer);
		}
		return lenBuffer; 
    }

    /**
     * Tests if this input stream supports the <code>mark</code> and
     * <code>reset</code> methods. The <code>markSupported</code>
     * method of <code>DecoderInputStream</code> returns
     * <code>false</code>.
     *
     * @return  a <code>boolean</code> indicating if this stream type supports
     *          the <code>mark</code> and <code>reset</code> methods.
     * @see     java.io.InputStream#mark(int)
     * @see     java.io.InputStream#reset()
     */
    public boolean markSupported() {
        return false;
    }
 
    /**
     * Marks the current position in this input stream.
     *
     * <p> The <code>mark</code> method of <code>DecoderInputStream</code>
     * does nothing.
     *
     * @param   readlimit   the maximum limit of bytes that can be read before
     *                      the mark position becomes invalid.
     * @see     java.io.InputStream#reset()
     */
    public synchronized void mark(final int readlimit) {
    }
 
    /**
     * Repositions this stream to the position at the time the
     * <code>mark</code> method was last called on this input stream.
     *
     * <p> The method <code>reset</code> for class
     * <code>DecoderInputStream</code> does nothing except throw an
     * <code>IOException</code>.
     *
     * @exception  IOException  if this method is invoked.
     * @see     java.io.InputStream#mark(int)
     * @see     java.io.IOException
     */
    public synchronized void reset() throws IOException {
        throw new IOException("mark/reset not supported");
    }
}
