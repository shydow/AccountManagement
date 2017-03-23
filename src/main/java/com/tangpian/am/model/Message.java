package com.tangpian.am.model;

import java.util.Date;

/**
 * 
 * 用于封装报文的类，其中data为用于存储的基础信息
 * 
 * @author shydow
 *
 */
public class Message<T> {
	public static final String DEFAULT_ISSUER = "tangpian.com";
	public static final int DEFAULT_AVAILABLE_PERIOD = 3;
	public static final String DEFAULT_VERSION = "1.0";
	
	private String issuer = DEFAULT_ISSUER;
	private Date issueTime = new Date();
	private String version = DEFAULT_VERSION;
	private int availablePeriod = DEFAULT_AVAILABLE_PERIOD;
	
	private T data;
	
	public Message() {
		// TODO Auto-generated constructor stub
	}
	
	public Message(T data) {
		this.data = data;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public Date getIssueTime() {
		return issueTime;
	}

	public void setIssueTime(Date issueTime) {
		this.issueTime = issueTime;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public int getAvailablePeriod() {
		return availablePeriod;
	}

	public void setAvailablePeriod(int availablePeriod) {
		this.availablePeriod = availablePeriod;
	}

	public T getData() {
		return data;
	}

	public void setData(T data) {
		this.data = data;
	}
}
