package com.hzih.ldap;/*
 * Copyright (c) 1995 - 2008 Sun Microsystems, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import com.hzih.ca.entity.X509Ca;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.*;

/**
 * Shows how a paged search can be performed using the PagedResultsControl API
 */

class PagedSearch {

    public static List<X509Ca> listX509Cas(int pageIndex, int pageSize) {
        List<X509Ca> x509Cas = new ArrayList<X509Ca>();

        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:10389/");
        env.put(Context.SECURITY_PRINCIPAL, "uid=admin,ou=system");
        env.put(Context.SECURITY_CREDENTIALS, "secret");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        try {
            LdapContext ctx = new InitialLdapContext(env, null);
            String sortKey = "cn";
            // Activate paged results
            byte[] cookie = null;
            ctx.setRequestControls(new Control[]{new PagedResultsControl(pageSize, Control.NONCRITICAL),new SortControl(sortKey,
                    Control.CRITICAL)});
            int total = 0;

            do {
            /* perform the search */
                pageIndex ++;
                SearchControls sc = new SearchControls();
                sc.setSearchScope(SearchControls.SUBTREE_SCOPE);
//        String filtro = "(&(sAMAccountName=*)&(objectClass=user))";
                NamingEnumeration results = ctx.search("dc=example,dc=com", "(objectclass=X509Ca)", sc);

            /* for each entry */
                while (results.hasMoreElements()) {
                    SearchResult result = (SearchResult) results.nextElement();
                    Attributes attributes = result.getAttributes();
                    //convert to MyUser class
                    X509Ca x509Ca = toX509Ca(attributes);
                    x509Cas.add(x509Ca);
                    total++;
                }

                // Examine the paged results control response
                Control[] controls = ctx.getResponseControls();
                cookie = parseControls(controls);
                /*if (controls != null) {
                    for (int i = 0; i < controls.length; i++) {
                        if (controls[i] instanceof PagedResultsResponseControl) {
                            PagedResultsResponseControl prrc = (PagedResultsResponseControl) controls[i];
                            total = prrc.getResultSize();
                            if (total != 0) {
                                System.out.println("***************** END-OF-PAGE " + "(total : " + total + ") *****************\n");
                            } else {
                                System.out.println("***************** END-OF-PAGE " + "(total: unknown) ***************\n");
                            }
                            cookie = prrc.getCookie();
                        }
                    }
                } else {
                    System.out.println("No controls were sent from the server");
                }*/
                // Re-activate paged results
                ctx.setRequestControls(new Control[]{new PagedResultsControl(pageSize, cookie, Control.CRITICAL)});

            } while (cookie != null&& (cookie.length != 0));

            ctx.close();

        } catch (NamingException e) {
            System.err.println("PagedSearch failed.");
            e.printStackTrace();
        } catch (IOException ie) {
            System.err.println("PagedSearch failed.");
            ie.printStackTrace();
        } catch (Exception ie) {
            System.err.println("PagedSearch failed.");
            ie.printStackTrace();
        }
        return x509Cas;
    }

    private static X509Ca toX509Ca(Attributes attributes) throws NamingException {
        if (attributes != null) {
            String fullName = attributes.get("distinguishedName") != null ? attributes.get("distinguishedName").get().toString() : null;
            String cn = attributes.get("cn") != null ? attributes.get("cn").get().toString() : null;
            X509Ca x509Ca = new X509Ca();
            x509Ca.setDn(fullName);
            x509Ca.setCn(cn);
            return x509Ca;
        }
        return null;
    }

    private static byte[] parseControls(Control[] controls) throws NamingException {
        byte[] cookie = null;
        if (controls != null) {
            for (int i = 0; i < controls.length; i++) {
                if (controls[i] instanceof PagedResultsResponseControl) {
                    PagedResultsResponseControl prrc = (PagedResultsResponseControl) controls[i];
                    cookie = prrc.getCookie();
                    System.out.println(">>Next Page \n");
                }else if(controls[i] instanceof SortResponseControl) {
                    SortResponseControl src = (SortResponseControl) controls[i];
                    if (!src.isSorted()) {
                        throw src.getException();
                    }
                }
            }
        }
        return (cookie == null) ? new byte[0] : cookie;
    }

    public static void main(String[] args) {
        List<X509Ca> x509Cas = listX509Cas(0, 10);
        for (X509Ca x509Ca : x509Cas) {
            System.out.println(x509Ca.getCn());
        }

    /*Hashtable<String, Object> env = new Hashtable<String, Object>(11);
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");

    *//* Specify host and port to use for directory service *//*
    env.put(Context.PROVIDER_URL,"ldap://localhost:10389/");
    env.put(Context.SECURITY_PRINCIPAL,"uid=admin,ou=system");
    env.put(Context.SECURITY_CREDENTIALS,"secret");
    env.put(Context.SECURITY_AUTHENTICATION,"simple");

//    env.put(Context.PROVIDER_URL,"ldap://localhost:389/");
//    env.put(Context.SECURITY_PRINCIPAL,"cn=admin,dc=pkica");
//    env.put(Context.SECURITY_CREDENTIALS,"123456");
//    env.put(Context.SECURITY_AUTHENTICATION,"simple");

    try {
      LdapContext ctx = new InitialLdapContext(env, null);

      // Activate paged results
      int pageSize = 3;
      byte[] cookie = null;

      ctx.setRequestControls(new Control[] { new PagedResultsControl(pageSize,Control.NONCRITICAL) });
      int total =0;

      do {
        *//* perform the search *//*
        NamingEnumeration results = ctx.search("dc=example,dc=com", "(objectclass=*)",
//        NamingEnumeration results = ctx.search("dc=pkica", "(objectclass=*)",
            new SearchControls());

        *//* for each entry print out name + all attrs and values *//*
        while (results != null && results.hasMore()) {
          SearchResult entry = (SearchResult) results.next();
          System.out.println(entry.getName());
          total++;
        }

        // Examine the paged results control response
        Control[] controls = ctx.getResponseControls();
        if (controls != null) {
          for (int i = 0; i < controls.length; i++) {
            if (controls[i] instanceof PagedResultsResponseControl) {
              PagedResultsResponseControl prrc = (PagedResultsResponseControl) controls[i];
//              total = prrc.getResultSize();
              if (total != 0) {
                System.out.println("***************** END-OF-PAGE "
                    + "(total : " + total + ") *****************\n");
              } else {
                System.out.println("***************** END-OF-PAGE "
                    + "(total: unknown) ***************\n");
              }
              cookie = prrc.getCookie();
            }
          }
        } else {
          System.out.println("No controls were sent from the server");
        }
        // Re-activate paged results
        ctx.setRequestControls(new Control[] { new PagedResultsControl(pageSize, cookie, Control.CRITICAL) });

      } while ((cookie != null) && (cookie.length != 0));

      ctx.close();
      System.out.println("Total = " + total);
    } catch (NamingException e) {
      System.err.println("PagedSearch failed.");
      e.printStackTrace();
    } catch (IOException ie) {
      System.err.println("PagedSearch failed.");
      ie.printStackTrace();
    }*/

    }
}