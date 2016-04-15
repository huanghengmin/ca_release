package com.hzih.ca.dao;

import com.hzih.ca.entity.X509Ca;

import javax.naming.directory.DirContext;

/**
 * Created by IntelliJ IDEA.
 * User: hhm
 * Date: 12-8-21
 * Time: 下午2:54
 * To change this template use File | Settings | File Templates.
 */
public interface X509CaDao {

    public boolean add(DirContext ctx, X509Ca x509Ca);

    public boolean modify(DirContext ctx,X509Ca x509Ca);

    public boolean deleteStation(DirContext ctx,String DN);
}
