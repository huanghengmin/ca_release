import junit.framework.TestCase;
import org.apache.commons.net.PrintCommandListener;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPClientConfig;
import org.apache.commons.net.ftp.FTPFile;
import org.apache.commons.net.ftp.FTPReply;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * Created with IntelliJ IDEA.
 * User: Administrator
 * Date: 14-7-23
 * Time: 下午4:01
 * To change this template use File | Settings | File Templates.
 */
public class TestFtpFileList extends TestCase {
    FTPClient client = new FTPClient();
        private static final String charset = "gbk";
//    private static final String charset = "utf-8";

    public void testFtpLogin() {
        String hostname = "192.168.1.89";
        int port = 21;
        String username = "ftpclient";
        String password = "12345678";

       /* String hostname = "192.168.1.128";
        int port = 21;
        String username = "test";
        String password = "123456";*/

        /*String hostname = "127.0.0.1";
        int port = 21;
        String username = "hhm";
        String password = "hhm";*/
        boolean isConnectOk = false;
        while (!isConnectOk) {
            try {

                client.connect(hostname, port);
                client.setControlEncoding(charset);

                if (FTPReply.isPositiveCompletion(client.getReplyCode())) {
                    if (client.login(username, password)) {
                        client.enterLocalPassiveMode();
                        client.setFileType(FTPClient.BINARY_FILE_TYPE);
                        isConnectOk = true;
                    } else {
//                        disconnect();
                    }
                } else {
//                    disconnect();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        if (isConnectOk) {

//            listDirectors("/zttftp");
            listDirectors("/");
        }
    }

    /*public void listFilesDir(String pathName, FTPClient ftp) throws IOException {
        if (pathName.startsWith("/") && pathName.endsWith("/")) {
            String directory = pathName;

            ftp.changeWorkingDirectory(directory);
            FTPFile[] files = ftp.listFiles();
            for (int i = 0; i < files.length; i++) {
                if (files[i].isDirectory()) {

                    listFilesDir(directory + files[i].getName() + "/", ftp);

                } else {
                    System.out.println("得到文件:" + files[i].getName());

                }
            }
        }
    }*/

   /* public void listAllFiles(String remotePath) {
        try {
            if (true) {
                FTPFile[] files = client.listFiles(remotePath);
                if(files != null){
                    for (int i = 0; i < files.length; i++) {
                        System.out.println(remotePath + "/" + files[i].getName());
                        if (files[i].isFile()) {
                            System.out.println(files[i].getName());
                        } else if (files[i].isDirectory()) {
                            listAllFiles(remotePath + "/"+ files[i].getName() );
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }*/

    public void listDirectors(String parent) {
        listFiles(parent);
        FTPFile[] dirs = new FTPFile[0];
        boolean isSuccess = false;
        int count = 0;
        do {
            count++;
            try {
//                dirs = client.listFiles(new String(parent));
               /* if(parent.contains(" ")){
                    parent=parent.replaceAll("%", "%25");//先将地址本身带有的%转为%25
                    parent=parent.replaceAll(" ", "%20");//再将空格转换为%20
                }*/
                String dir = new String(parent.getBytes(charset), "iso-8859-1");
//                dirs = client.listFiles(new String(parent.getBytes("GBK"),"iso-8859-1"));
//                System.out.print(dir);
                dirs = client.listFiles(dir);

//                dirs = client.listFiles(parent);

                isSuccess = true;
            } catch (Exception e) {
                e.printStackTrace();
//                System.out.println(e);
            } finally {
            }
        } while (!isSuccess && count <= 10);
        int idx = 0;//无用的文件夹           //todo
        for (int i = 0; i < dirs.length; i++) {
            if (idx == 2 && dirs.length == 2) {
                return;
            }
            if (!dirs[i].isDirectory()) {
                continue;
            }
            String dirName = dirs[i].getName();
            if (".".equals(dirName) || "..".equals(dirName)) {
                idx++;
                continue;
            }
            String _parent = null;
            if (parent.endsWith("/")) {
                _parent = parent + dirName;
            } else {
                _parent = parent + "/" + dirName;
            }
            listDirectors(_parent);
        }
    }

    private void listFiles(String parent) {
        FTPFile[] files = new FTPFile[0];
//        FTPSendFileFilter ftpSendFileFilter = new FTPSendFileFilter(config);
        boolean isSuccess = false;
        do {
            try {
//                files = client.listFiles(new String(parent));
                /*if(parent.contains(" ")){
                    parent=parent.replaceAll("%", "%25");//先将地址本身带有的%转为%25
                    parent=parent.replaceAll(" ", "%20");//再将空格转换为%20
                }*/
//                files = client.listFiles(new String(parent.getBytes("GBK"),"iso-8859-1"));

//                files = client.listFiles(new String(parent.getBytes(),"iso-8859-1"));

                String dir = new String(parent.getBytes(charset), "iso-8859-1");

//                System.out.print(dir);

                files = client.listFiles(dir);

//                files = client.listFiles(parent);

                if (files != null && files.length > 0) {
                    for (int i = 0; i < files.length; i++) {
                        if (files[i].isDirectory()) {
                            System.out.println("目录::::::::" + parent + "/" + files[i].getName());
                        } else {
                            System.out.println("文件::::::::::::" + parent + "/" + files[i].getName());
                        }

                    }
                }
                isSuccess = true;
            } catch (Exception e) {
//                System.out.println("获取文件列表错误");
//                System.out.println(e);
                e.printStackTrace();
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
                }
            } finally {
//                complete();
            }
        } while (!isSuccess);
    }


}
