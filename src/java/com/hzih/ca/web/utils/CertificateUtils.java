package com.hzih.ca.web.utils;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERConstructedSequence;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 14-7-3
 * Time: 下午9:33
 * To change this template use File | Settings | File Templates.
 */
public class CertificateUtils {
    private Logger logger = Logger.getLogger(CertificateUtils.class);

    /**
     * 国家
     */
    private String C = "C";
    /**
     * 通用名
     */
    private String CN = "CN";
    /**
     *部门u
     */
    private String OU = "OU";
    /**
     * 单位
     */
    private String O = "O";
    /**
     * 省
     */
    private String ST = "ST";
    /**
     * 市
     */
    private String L = "L";
    /**
     * Email
     */
    private String E = "E";



    public String getSubject(String subject,String t){
           if(subject.contains(t)){

           }
        return null;
    }



    public X509Certificate get_x509_certificate(File cerFile) {
        CertificateFactory certificatefactory = null;
        try {
            certificatefactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            logger.error(e.getMessage(),e);
        }
        FileInputStream cerIs = null;
        X509Certificate cert = null;
        try {
            cerIs = new FileInputStream(cerFile);
            cert = (X509Certificate) certificatefactory.generateCertificate(cerIs);
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
        }finally {
            try {
                cerIs.close();
            } catch (IOException e) {
                logger.error(e.getMessage(),e);
            }
        }
        return cert;
    }

    public static PKCS10CertificationRequest getPKCS10CertificationRequest(File file)throws Exception{
        byte[] b64Encoded = readFiletoBuffer(file);
        byte[] buffer;
        try {
            String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
            String endKey = "-----END CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        } catch (IOException e) {
            e.printStackTrace();
            String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
            String endKey = "-----END NEW CERTIFICATE REQUEST-----";
            buffer = getBytesFromPEM(b64Encoded, beginKey, endKey);
        }
        PKCS10CertificationRequest pkcs10 = createCertificate(buffer);
        return pkcs10;
    }

    /**
     * Helpfunction to read a file to a byte array.
     *
     *@param file filename of file.
     *@return byte[] containing the contents of the file.
     *@exception IOException if the file does not exist or cannot be read.
     **/
    public static byte[] readFiletoBuffer(File file) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        InputStream in = new FileInputStream(file);
        int len = 0;
        byte buf[] = new byte[1024];
        while ((len = in.read(buf)) > 0)
            os.write(buf, 0, len);
        in.close();
        os.close();
        return os.toByteArray();
    }


    /**
     *
     * @param inbuf
     * @param beginKey
     * @param endKey
     * @return
     * @throws IOException
     */
    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)throws IOException {
        ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        PrintStream opstr = new PrintStream(ostr);
        String temp;
        while ((temp = bufRdr.readLine()) != null &&
                !temp.equals(beginKey))
            continue;
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
        while ((temp = bufRdr.readLine()) != null &&
                !temp.equals(endKey))
            opstr.print(temp);
        if (temp == null)
            throw new IOException("Error in input buffer, missing " + endKey + " boundary");
        opstr.close();

        byte[] bytes = Base64.decode(ostr.toByteArray());

        return bytes;
    }


    /**
     *
     * @param pkcs10req
     * @return
     * @throws IOException
     */
    public static PKCS10CertificationRequest createCertificate(byte[] pkcs10req) throws IOException {
        DERObject derobj  = new DERInputStream(new ByteArrayInputStream(pkcs10req)).readObject();
        DERConstructedSequence seq = (DERConstructedSequence)derobj;
        PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(seq);
        return pkcs10;
    }
}
