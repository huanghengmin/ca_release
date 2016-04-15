package com.hzih.ca.service;

import com.hzih.ca.entity.X509User;

import javax.naming.directory.DirContext;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-22
 * Time: 下午2:45
 * 服务层
 */
public interface X509UserService {
    public boolean add(X509User x509User)throws Exception;

    public boolean modify(X509User x509User)throws Exception;

    public boolean delete(String DN)throws Exception;


    public boolean exist(String DN)throws Exception;
}
