package com.hzih.ca.web.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

/**
 * Created with IntelliJ IDEA.
 * User: hhm
 * Date: 12-11-8
 * Time: 下午11:28
 * To change this template use File | Settings | File Templates.
 */
public class FileHandles {
    /**
     * 读取文件内容
     * @param file  文件对象
     * @return    文件内容
     */
    public static String readFileByLines(File file) {
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader reader = null;
        FileReader fr = null;
        try {
            fr = new FileReader(file);
            reader = new BufferedReader(fr);
            String tempString = null;
            while ((tempString = reader.readLine()) != null) {
                stringBuilder.append(tempString);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                    fr.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
        return stringBuilder.toString();
    }

    public static String readFileByLines(String  path) {
        File file = new File(path);
        if(file.exists()){
            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader reader = null;
            FileReader fr = null;
            try {
                fr =new FileReader(file);
                reader = new BufferedReader(fr);
                String tempString = null;
                while ((tempString = reader.readLine()) != null) {
                    stringBuilder.append(tempString);
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                        fr.close();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                }
            }
            return stringBuilder.toString();
        }
         return null;
    }
}
