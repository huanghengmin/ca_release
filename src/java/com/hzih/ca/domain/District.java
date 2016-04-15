package com.hzih.ca.domain;

/**
 * 帐号，用户
 * 
 * @author www
 * @hibernate.class table="district"
 */
public class District {
	
	/**
	 * @hibernate.id column="district_id" generator-class="increment" type="long"
	 *               length="11"
	 */
    Long id;
	
	/**
	 * 地区名
	 * 
	 * @hibernate.property column="district_name" type="string" length="20"
	 */
	String districtName;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getDistrictName() {
        return districtName;
    }

    public void setDistrictName(String districtName) {
        this.districtName = districtName;
    }
}
