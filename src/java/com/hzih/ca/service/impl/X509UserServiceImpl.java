package com.hzih.ca.service.impl;

import com.hzih.ca.dao.X509UserDao;
import com.hzih.ca.entity.X509User;
import com.hzih.ca.service.X509UserService;

import javax.naming.directory.DirContext;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-22
 * Time: 下午2:46
 * To change this template use File | Settings | File Templates.
 */
public class X509UserServiceImpl implements X509UserService {
    private X509UserDao x509UserDao;

    public X509UserDao getX509UserDao() {
        return x509UserDao;
    }

    public void setX509UserDao(X509UserDao x509UserDao) {
        this.x509UserDao = x509UserDao;
    }

    @Override
    public boolean add(X509User x509User)throws Exception{
       return x509UserDao.add(x509User);
    }

    @Override
    public boolean modify(X509User x509User)throws Exception {
        return x509UserDao.modify(x509User);
    }

    @Override
    public boolean delete(String DN) throws Exception{
        return x509UserDao.delete(DN);
    }

    @Override
    public boolean exist(String DN) throws Exception {
        return x509UserDao.exist(DN);
    }
}
