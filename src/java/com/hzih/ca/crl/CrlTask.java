package com.hzih.ca.crl;

import java.util.TimerTask;

public class CrlTask extends TimerTask {
    /**
     * Crl更新类
     */

    @Override
    public void run() {
        /**
         * 更新CRL列表文件
         */
        CrlTaskExecute execute = new CrlTaskExecute();
        execute.CRL();
    }
}