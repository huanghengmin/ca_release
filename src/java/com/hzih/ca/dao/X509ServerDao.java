package com.hzih.ca.dao;

import com.hzih.ca.entity.X509Server;

import javax.naming.directory.DirContext;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-22
 * Time: 下午2:44
 * hzihdevice dao 层
 */
public interface X509ServerDao {
    public boolean add(X509Server x509Server)throws Exception;

    public boolean modify(X509Server x509Server)throws Exception;

    public boolean delete(String DN)throws Exception;
}
