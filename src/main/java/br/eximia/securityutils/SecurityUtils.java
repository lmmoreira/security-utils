package br.eximia.securityutils;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public final class SecurityUtils {
	
    private SecurityUtils() {
    }
    
    public static UserDetails getUser(){
    	
    	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    	
    	if (!((authentication == null) || (authentication instanceof AnonymousAuthenticationToken))) {
    		return (User) authentication.getPrincipal();
    	}
    	
    	return null;
    
    }
    
    public static String userName() {
    	
    	UserDetails user = SecurityUtils.getUser();
    	
    	if(user != null){
    		return user.getUsername();
    	}
    	
    	return null;
    	
    }
    
    public static String roles() {
    	
    	UserDetails user = SecurityUtils.getUser();
    	
    	String roles = "";
    	
    	if(user != null){
    		
    		for(GrantedAuthority authority : user.getAuthorities()){
    			roles += authority.getAuthority() + ", ";
    		}
    		
    		if(!roles.isEmpty()){
    			roles = roles.substring(0, roles.length() - 2);
    		}
    		
    		return roles;
    		
    	}
    	
    	return null;
    	
    }

    public static Boolean isAuthenticated() {
    	return (SecurityUtils.getUser() != null);
    }
    
    public static Boolean isNotAuthenticated() {
    	return (!isAuthenticated());
    }
    
    public static Boolean ifAreAllGranted(String roles) {
    	
    	UserDetails user = SecurityUtils.getUser();
    	
    	if(user == null)
    		return false;
    	
    	String[] arRoles = roles.split(",");
    	boolean granted = false;
    	
    	for(String sRole : arRoles){
	    	for(GrantedAuthority authority : user.getAuthorities()){
	    		if(authority.getAuthority().equals(sRole.trim())){
	    			granted = true;
	    			break;
	    		}
	    	}
    	}
    	
    	return granted;
    }
    
    public static Boolean ifAreAnyGranted(String roles) {
    	UserDetails user = SecurityUtils.getUser();
    	
    	if(user == null)
    		return false;
    	
    	String[] arRoles = roles.split(",");
    	boolean granted = false;
    	
    	for(String sRole : arRoles){
	    	for(GrantedAuthority authority : user.getAuthorities()){
	    		if(authority.getAuthority().equals(sRole.trim())){
	    			granted = true;
	    			break;
	    		}
	    	}
    	}
    	
    	return granted;
    }
    
    public static Boolean ifAreNotGranted(String roles) {
    	return !ifAreAllGranted(roles);
    }

}
    