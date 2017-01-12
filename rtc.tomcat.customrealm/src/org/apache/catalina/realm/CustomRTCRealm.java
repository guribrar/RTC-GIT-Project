package org.apache.catalina.realm;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;

import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.realm.User;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.JNDIRealm;

public class CustomRTCRealm extends JNDIRealm {

	private static final Logger _logger = Logger.getLogger(CustomRTCRealm.class.getName());

	protected String _buildPassword = "pass_4_build";
	
	protected String _buildUser = "build";
	
	protected String _buildRoles = "JazzUsers,JazzAdmins";
	
	
	private ArrayList getBuildRoleList() {
		
		ArrayList<String> roles = new ArrayList<String>();
		String[] tmp = _buildRoles.split(",");
		for (int i = 0; i < tmp.length; i++) {
			roles.add(tmp[i]);
		}
		return roles;
	}
	
	
	
	@Override
	public Principal authenticate(String username, String credentials) {

		_logger.info("authentciate1: " + username);
		
		// check our build user first..
		if (username != null && username.equalsIgnoreCase(_buildUser)) {
			if (credentials.equalsIgnoreCase(_buildPassword)) {
				return new GenericPrincipal(this, username, credentials, getBuildRoleList());					
			} else {
				_logger.severe("Invalid credentials for build user or missing config!");
				return null;
			}
		}

		return super.authenticate(username, credentials); 
	}

	
	@Override
	protected Principal getPrincipal(String username) {
		
		_logger.info("getPrincipal1: " + username);
		
		if (username != null && username.equalsIgnoreCase(_buildUser)) {			
			return new GenericPrincipal(this, username, _buildPassword, getBuildRoleList());				
		}				
		return super.getPrincipal(username);
	}


	public String getBuildPassword() {
		return _buildPassword;
	}

	public void setBuildPassword(String buildPassword) {
		_buildPassword = buildPassword;
	}

	public String getBuildUser() {
		return _buildUser;
	}

	public void setBuildUser(String buildUser) {
		_buildUser = buildUser;
	}

	public String getBuildRoles() {
		return _buildRoles;
	}

	public void setBuildRoles(String buildRoles) {
		_buildRoles = buildRoles;
	}


	@Override
	public synchronized Principal authenticate(DirContext context, String username, String credentials) throws NamingException {
		_logger.info("authenticate: " + username);

		if (username != null && username.equalsIgnoreCase(_buildUser)) {
			return authenticate(username, credentials);
		}		
		return super.authenticate(context, username, credentials);
	}


	@Override
	protected boolean checkCredentials(DirContext context, User user, String credentials) throws NamingException {
		// TODO Auto-generated method stub
		_logger.info("checkcredentials");
		return super.checkCredentials(context, user, credentials);
	}


	@Override
	protected boolean compareCredentials(DirContext context, User info, String credentials) throws NamingException {
		// TODO Auto-generated method stub
		_logger.info("comparecredentials");
		return super.compareCredentials(context, info, credentials);
	}


	@Override
	protected synchronized Principal getPrincipal(DirContext context, String username) throws NamingException {
		// TODO Auto-generated method stub
		_logger.info("getPrincipal: " + username);
		return super.getPrincipal(context, username);
	}


	@Override
	protected List getRoles(DirContext context, User user) throws NamingException {
		_logger.info("getRoles: " + user.username);
		return super.getRoles(context, user);
	}


	@Override
	protected User getUser(DirContext context, String username) throws NamingException {

		_logger.info("getUser: " + username);
		if (username != null && username.equalsIgnoreCase(_buildUser)) {
			User user = new User(_buildUser, "build", _buildPassword, getBuildRoleList());
			return user;
		}
		
		return super.getUser(context, username);
	}


	@Override
	protected User getUserByPattern(DirContext context, String username, String[] attrIds) throws NamingException {
		_logger.info("getUserByPattern: " + username);
		return super.getUserByPattern(context, username, attrIds);
	}


	@Override
	protected User getUserBySearch(DirContext context, String username, String[] attrIds) throws NamingException {
		_logger.info("getUserBySearch: " + username);
		if (username != null && username.equalsIgnoreCase(_buildUser)) {
			User user = new User(_buildUser, "build", _buildPassword, getBuildRoleList());
			return user;
		}
		
		return super.getUserBySearch(context, username, attrIds);
	}



	@Override
	public boolean hasResourcePermission(Request request, Response response, SecurityConstraint[] constraints, Context context) throws IOException {
		
		boolean result = super.hasResourcePermission(request, response, constraints, context); 
		
		if (!result) {
			_logger.info("hasResourcePermission denied for " + request.getServletPath() +  " / " + request.getQueryString());	
		}
		
		return result;
	}

	
}
