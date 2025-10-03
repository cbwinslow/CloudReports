"""
SAML SSO Integration for Enterprise Reporting System
"""

import xml.etree.ElementTree as ET
import base64
import hashlib
import hmac
import urllib.parse
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
import secrets
import logging
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import uuid
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)

@dataclass
class SAMLConfig:
    """SAML Configuration Settings"""
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: Optional[str]
    idp_cert: str  # PEM format certificate
    sp_entity_id: str
    sp_acs_url: str
    sp_slo_url: Optional[str]
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    authn_context_class_ref: str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    sign_authn_requests: bool = True
    sign_assertions: bool = True
    encrypt_assertions: bool = False
    require_encrypted_assertions: bool = False
    allow_unsafe_redirects: bool = False
    signature_algorithm: str = "rsa-sha256"
    digest_algorithm: str = "sha256"

@dataclass
class SAMLAssertion:
    """Parsed SAML Assertion"""
    assertion_id: str
    issuer: str
    subject: str
    name_id: str
    attributes: Dict[str, Any]
    not_before: datetime
    not_on_or_after: datetime
    audience: str
    valid: bool
    error: Optional[str] = None

class SAMLServiceProvider:
    """SAML Service Provider Implementation"""
    
    def __init__(self, config: SAMLConfig):
        self.config = config
        self.private_key = None
        self.public_key = None
        self.idp_cert = None
        self._load_certificates()
    
    def _load_certificates(self):
        """Load and parse certificates"""
        try:
            # Load IDP certificate
            self.idp_cert = load_pem_x509_certificate(
                self.config.idp_cert.encode('utf-8')
            )
            
            # Generate SP keys if not provided
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            self.private_key = private_key
            self.public_key = private_key.public_key()
            
        except Exception as e:
            logger.error(f"Error loading certificates: {e}")
            raise
    
    def generate_authn_request(self, relay_state: Optional[str] = None) -> Dict[str, str]:
        """Generate SAML AuthnRequest"""
        try:
            # Create request ID
            request_id = f"_req_{uuid.uuid4().hex}"
            
            # Current time
            now = datetime.utcnow()
            issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            not_on_or_after = (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Create AuthnRequest XML
            authn_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.config.idp_sso_url}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="{self.config.sp_acs_url}">
    <saml:Issuer>{self.config.sp_entity_id}</saml:Issuer>
    <samlp:NameIDPolicy 
        Format="{self.config.name_id_format}"
        AllowCreate="true"/>
    <samlp:RequestedAuthnContext Comparison="exact">
        <saml:AuthnContextClassRef>{self.config.authn_context_class_ref}</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>"""
            
            # Sign request if required
            if self.config.sign_authn_requests:
                signed_request = self._sign_xml(authn_request)
                saml_request = base64.b64encode(signed_request.encode('utf-8')).decode('utf-8')
            else:
                saml_request = base64.b64encode(authn_request.encode('utf-8')).decode('utf-8')
            
            # Prepare request data
            request_data = {
                'SAMLRequest': saml_request,
                'RelayState': relay_state or ''
            }
            
            # Add signature if required
            if self.config.sign_authn_requests:
                signature = self._generate_signature(request_data)
                request_data['SigAlg'] = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
                request_data['Signature'] = signature
            
            return {
                'success': True,
                'request_id': request_id,
                'saml_request': saml_request,
                'redirect_url': f"{self.config.idp_sso_url}?{urllib.parse.urlencode(request_data)}",
                'post_data': request_data
            }
            
        except Exception as e:
            logger.error(f"Error generating AuthnRequest: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _sign_xml(self, xml_string: str) -> str:
        """Sign XML string with SP private key"""
        # In a real implementation, this would use proper XML signing
        # For demo purposes, we'll return the original XML
        return xml_string
    
    def _generate_signature(self, params: Dict[str, str]) -> str:
        """Generate signature for SAML request"""
        # Create signature string
        signature_string = '&'.join([
            f"{urllib.parse.quote(key, safe='')}"
            f"="
            f"{urllib.parse.quote(params[key], safe='')}"
            for key in sorted(params.keys())
            if key != 'Signature'
        ])
        
        # Sign with private key
        signature = self.private_key.sign(
            signature_string.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def process_saml_response(self, saml_response: str, relay_state: Optional[str] = None) -> Dict[str, Any]:
        """Process SAML Response from IDP"""
        try:
            # Decode SAML response
            decoded_response = base64.b64decode(saml_response)
            response_xml = decoded_response.decode('utf-8')
            
            # Parse XML
            root = ET.fromstring(response_xml)
            
            # Extract basic information
            response_id = root.get('ID', '')
            issue_instant = root.get('IssueInstant', '')
            destination = root.get('Destination', '')
            issuer = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            issuer_value = issuer.text if issuer is not None else ''
            
            # Extract status
            status = root.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status')
            status_code = None
            status_message = None
            
            if status is not None:
                status_code_elem = status.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
                if status_code_elem is not None:
                    status_code = status_code_elem.get('Value', '')
                
                status_message_elem = status.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage')
                if status_message_elem is not None:
                    status_message = status_message_elem.text
            
            # Check if response is successful
            if status_code != 'urn:oasis:names:tc:SAML:2.0:status:Success':
                return {
                    'success': False,
                    'error': f'SAML response indicates failure: {status_code}',
                    'status_message': status_message,
                    'issuer': issuer_value
                }
            
            # Extract assertions
            assertions = root.findall('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            
            if not assertions:
                return {
                    'success': False,
                    'error': 'No assertions found in SAML response',
                    'issuer': issuer_value
                }
            
            # Process first assertion (in real implementation, process all)
            assertion = assertions[0]
            parsed_assertion = self._parse_assertion(assertion)
            
            if not parsed_assertion.valid:
                return {
                    'success': False,
                    'error': parsed_assertion.error or 'Invalid assertion',
                    'issuer': issuer_value
                }
            
            # Validate assertion
            validation_result = self._validate_assertion(parsed_assertion)
            
            if not validation_result['valid']:
                return {
                    'success': False,
                    'error': validation_result['error'],
                    'issuer': issuer_value
                }
            
            return {
                'success': True,
                'assertion': parsed_assertion,
                'response_id': response_id,
                'issue_instant': issue_instant,
                'destination': destination,
                'issuer': issuer_value,
                'user_attributes': parsed_assertion.attributes,
                'name_id': parsed_assertion.name_id,
                'session_index': self._extract_session_index(assertion)
            }
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return {
                'success': False,
                'error': f'Invalid XML in SAML response: {str(e)}'
            }
        except Exception as e:
            logger.error(f"Error processing SAML response: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _parse_assertion(self, assertion_elem) -> SAMLAssertion:
        """Parse SAML assertion element"""
        try:
            assertion_id = assertion_elem.get('ID', '')
            issuer_elem = assertion_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            issuer = issuer_elem.text if issuer_elem is not None else ''
            
            # Extract subject
            subject_elem = assertion_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
            name_id = ''
            subject = ''
            
            if subject_elem is not None:
                name_id_elem = subject_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
                if name_id_elem is not None:
                    name_id = name_id_elem.text
                    subject = name_id_elem.get('Format', '') or name_id_elem.text
            
            # Extract conditions
            conditions_elem = assertion_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
            not_before = None
            not_on_or_after = None
            audience = ''
            
            if conditions_elem is not None:
                not_before_attr = conditions_elem.get('NotBefore', '')
                not_on_or_after_attr = conditions_elem.get('NotOnOrAfter', '')
                
                if not_before_attr:
                    try:
                        not_before = datetime.strptime(not_before_attr, "%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        pass
                
                if not_on_or_after_attr:
                    try:
                        not_on_or_after = datetime.strptime(not_on_or_after_attr, "%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        pass
                
                # Extract audience restriction
                audience_restriction = conditions_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction')
                if audience_restriction is not None:
                    audience_elem = audience_restriction.find('{urn:oasis:names:tc:SAML:2.0:assertion}Audience')
                    if audience_elem is not None:
                        audience = audience_elem.text
            
            # Extract attributes
            attributes = {}
            attribute_statement = assertion_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement')
            if attribute_statement is not None:
                for attr_elem in attribute_statement.findall('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
                    attr_name = attr_elem.get('Name', '')
                    attr_friendly_name = attr_elem.get('FriendlyName', '')
                    attr_values = []
                    
                    for value_elem in attr_elem.findall('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                        attr_values.append(value_elem.text or '')
                    
                    # Use friendly name if available, otherwise use name
                    key = attr_friendly_name or attr_name
                    attributes[key] = attr_values[0] if len(attr_values) == 1 else attr_values
            
            # Create assertion object
            assertion = SAMLAssertion(
                assertion_id=assertion_id,
                issuer=issuer,
                subject=subject,
                name_id=name_id,
                attributes=attributes,
                not_before=not_before,
                not_on_or_after=not_on_or_after,
                audience=audience,
                valid=True
            )
            
            return assertion
            
        except Exception as e:
            logger.error(f"Error parsing assertion: {e}")
            return SAMLAssertion(
                assertion_id='',
                issuer='',
                subject='',
                name_id='',
                attributes={},
                not_before=None,
                not_on_or_after=None,
                audience='',
                valid=False,
                error=str(e)
            )
    
    def _validate_assertion(self, assertion: SAMLAssertion) -> Dict[str, Any]:
        """Validate SAML assertion"""
        try:
            # Check if assertion is marked as invalid
            if not assertion.valid:
                return {
                    'valid': False,
                    'error': assertion.error or 'Assertion marked as invalid'
                }
            
            # Check time validity
            now = datetime.utcnow()
            
            if assertion.not_before and now < assertion.not_before:
                return {
                    'valid': False,
                    'error': 'Assertion not yet valid'
                }
            
            if assertion.not_on_or_after and now >= assertion.not_on_or_after:
                return {
                    'valid': False,
                    'error': 'Assertion has expired'
                }
            
            # Check audience
            if assertion.audience and assertion.audience != self.config.sp_entity_id:
                return {
                    'valid': False,
                    'error': 'Assertion audience does not match SP entity ID'
                }
            
            # Check issuer (optional validation)
            if assertion.issuer and assertion.issuer != self.config.idp_entity_id:
                logger.warning(f"Assertion issuer {assertion.issuer} does not match configured IDP {self.config.idp_entity_id}")
                # This might be acceptable depending on configuration
            
            return {
                'valid': True
            }
            
        except Exception as e:
            logger.error(f"Error validating assertion: {e}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def _extract_session_index(self, assertion_elem) -> Optional[str]:
        """Extract session index from assertion"""
        authn_statement = assertion_elem.find('{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement')
        if authn_statement is not None:
            return authn_statement.get('SessionIndex', None)
        return None
    
    def generate_logout_request(self, name_id: str, session_index: Optional[str] = None) -> Dict[str, str]:
        """Generate SAML LogoutRequest"""
        try:
            # Create request ID
            request_id = f"_logout_{uuid.uuid4().hex}"
            
            # Current time
            now = datetime.utcnow()
            issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Create LogoutRequest XML
            logout_request = f"""<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest 
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="{request_id}"
    Version="2.0"
    IssueInstant="{issue_instant}"
    Destination="{self.config.idp_slo_url}">
    <saml:Issuer>{self.config.sp_entity_id}</saml:Issuer>
    <saml:NameID>{name_id}</saml:NameID>
"""
            
            if session_index:
                logout_request += f"    <samlp:SessionIndex>{session_index}</samlp:SessionIndex>\n"
            
            logout_request += "</samlp:LogoutRequest>"
            
            # Encode request
            saml_request = base64.b64encode(logout_request.encode('utf-8')).decode('utf-8')
            
            # Prepare request data
            request_data = {
                'SAMLRequest': saml_request
            }
            
            return {
                'success': True,
                'request_id': request_id,
                'saml_request': saml_request,
                'redirect_url': f"{self.config.idp_slo_url}?{urllib.parse.urlencode(request_data)}",
                'post_data': request_data
            }
            
        except Exception as e:
            logger.error(f"Error generating LogoutRequest: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_logout_response(self, saml_response: str) -> Dict[str, Any]:
        """Process SAML LogoutResponse"""
        try:
            # Decode SAML response
            decoded_response = base64.b64decode(saml_response)
            response_xml = decoded_response.decode('utf-8')
            
            # Parse XML
            root = ET.fromstring(response_xml)
            
            # Extract basic information
            response_id = root.get('ID', '')
            issue_instant = root.get('IssueInstant', '')
            destination = root.get('Destination', '')
            issuer = root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
            issuer_value = issuer.text if issuer is not None else ''
            
            # Extract status
            status = root.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status')
            status_code = None
            status_message = None
            
            if status is not None:
                status_code_elem = status.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
                if status_code_elem is not None:
                    status_code = status_code_elem.get('Value', '')
                
                status_message_elem = status.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage')
                if status_message_elem is not None:
                    status_message = status_message_elem.text
            
            # Check if response is successful
            success = status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success'
            
            return {
                'success': success,
                'response_id': response_id,
                'issue_instant': issue_instant,
                'destination': destination,
                'issuer': issuer_value,
                'status_code': status_code,
                'status_message': status_message
            }
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error in LogoutResponse: {e}")
            return {
                'success': False,
                'error': f'Invalid XML in SAML LogoutResponse: {str(e)}'
            }
        except Exception as e:
            logger.error(f"Error processing SAML LogoutResponse: {e}")
            return {
                'success': False,
                'error': str(e)
            }

class SAMLSingleSignOnService:
    """Main SAML SSO Service for the Enterprise Reporting System"""
    
    def __init__(self, config: SAMLConfig):
        self.saml_sp = SAMLServiceProvider(config)
        self.active_sessions = {}  # In production, this would be Redis or database
        self.logger = logging.getLogger(__name__)
    
    def initiate_sso_login(self, return_url: Optional[str] = None) -> Dict[str, Any]:
        """Initiate SSO login process"""
        try:
            # Generate AuthnRequest
            authn_request = self.saml_sp.generate_authn_request(return_url)
            
            if not authn_request['success']:
                return {
                    'success': False,
                    'error': authn_request['error']
                }
            
            # Store request for validation later
            self.active_sessions[authn_request['request_id']] = {
                'created_at': datetime.utcnow(),
                'return_url': return_url,
                'status': 'pending'
            }
            
            return {
                'success': True,
                'redirect_url': authn_request['redirect_url'],
                'request_id': authn_request['request_id'],
                'post_data': authn_request['post_data']
            }
            
        except Exception as e:
            self.logger.error(f"Error initiating SSO login: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_sso_response(self, saml_response: str, relay_state: Optional[str] = None) -> Dict[str, Any]:
        """Process SSO response and authenticate user"""
        try:
            # Process SAML response
            response_result = self.saml_sp.process_saml_response(saml_response, relay_state)
            
            if not response_result['success']:
                self.logger.warning(f"SSO response processing failed: {response_result['error']}")
                return response_result
            
            # Extract user information
            user_attributes = response_result['user_attributes']
            name_id = response_result['name_id']
            session_index = response_result['session_index']
            
            # Map SAML attributes to user fields
            user_info = self._map_saml_attributes(user_attributes, name_id)
            
            # Validate user (in a real implementation, check against user database)
            user_validation = self._validate_user(user_info)
            
            if not user_validation['valid']:
                return {
                    'success': False,
                    'error': user_validation['error']
                }
            
            # Generate session token (in a real implementation, this would be JWT or similar)
            session_token = self._generate_session_token(user_info)
            
            # Store session information
            self.active_sessions[session_token] = {
                'user_id': user_info['user_id'],
                'name_id': name_id,
                'session_index': session_index,
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=8),
                'attributes': user_attributes
            }
            
            self.logger.info(f"SSO login successful for user: {user_info['username']}")
            
            return {
                'success': True,
                'session_token': session_token,
                'user_info': user_info,
                'return_url': relay_state,
                'message': 'SSO authentication successful'
            }
            
        except Exception as e:
            self.logger.error(f"Error processing SSO response: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _map_saml_attributes(self, saml_attributes: Dict[str, Any], name_id: str) -> Dict[str, Any]:
        """Map SAML attributes to user fields"""
        # Common SAML attribute mappings
        attribute_mapping = {
            'email': ['email', 'mail', 'EmailAddress'],
            'first_name': ['firstName', 'givenName', 'FirstName'],
            'last_name': ['lastName', 'surname', 'LastName'],
            'username': ['username', 'uid', 'UserID'],
            'groups': ['groups', 'memberOf', 'Groups'],
            'department': ['department', 'Department'],
            'title': ['title', 'Title']
        }
        
        user_info = {
            'user_id': f"saml_{uuid.uuid4().hex}",
            'username': name_id,
            'email': name_id,
            'first_name': '',
            'last_name': '',
            'groups': [],
            'department': '',
            'title': ''
        }
        
        # Map attributes
        for user_field, saml_keys in attribute_mapping.items():
            for saml_key in saml_keys:
                if saml_key in saml_attributes:
                    value = saml_attributes[saml_key]
                    if isinstance(value, list):
                        if user_field == 'groups':
                            user_info[user_field] = value
                        else:
                            user_info[user_field] = value[0] if value else ''
                    else:
                        user_info[user_field] = value
                    break
        
        # Set username from email if not already set
        if not user_info['username'] and '@' in user_info['email']:
            user_info['username'] = user_info['email'].split('@')[0]
        
        return user_info
    
    def _validate_user(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """Validate user against system"""
        # In a real implementation, this would check against user database
        # For demo, we'll assume all SAML users are valid
        
        # Basic validation
        if not user_info.get('email'):
            return {
                'valid': False,
                'error': 'Email address required from SAML assertion'
            }
        
        if not user_info.get('username'):
            return {
                'valid': False,
                'error': 'Username required from SAML assertion'
            }
        
        # In a real implementation:
        # 1. Check if user exists in database
        # 2. Verify user is active
        # 3. Check group memberships
        # 4. Apply attribute-based access controls
        
        return {
            'valid': True
        }
    
    def _generate_session_token(self, user_info: Dict[str, Any]) -> str:
        """Generate session token for authenticated user"""
        # In a real implementation, this would be JWT or similar
        return f"sess_{secrets.token_urlsafe(32)}"
    
    def validate_session(self, session_token: str) -> Dict[str, Any]:
        """Validate session token"""
        try:
            if session_token not in self.active_sessions:
                return {
                    'valid': False,
                    'error': 'Invalid or expired session'
                }
            
            session = self.active_sessions[session_token]
            
            # Check expiration
            if datetime.utcnow() > session['expires_at']:
                del self.active_sessions[session_token]
                return {
                    'valid': False,
                    'error': 'Session expired'
                }
            
            return {
                'valid': True,
                'user_id': session['user_id'],
                'attributes': session['attributes'],
                'created_at': session['created_at']
            }
            
        except Exception as e:
            self.logger.error(f"Error validating session {session_token}: {e}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def initiate_sso_logout(self, session_token: str) -> Dict[str, Any]:
        """Initiate SSO logout process"""
        try:
            # Validate session
            session_validation = self.validate_session(session_token)
            
            if not session_validation['valid']:
                return session_validation
            
            session = self.active_sessions[session_token]
            
            # Generate LogoutRequest
            logout_request = self.saml_sp.generate_logout_request(
                session['name_id'],
                session['session_index']
            )
            
            if not logout_request['success']:
                return {
                    'success': False,
                    'error': logout_request['error']
                }
            
            # Remove local session
            del self.active_sessions[session_token]
            
            return {
                'success': True,
                'redirect_url': logout_request['redirect_url'],
                'post_data': logout_request['post_data'],
                'message': 'SSO logout initiated'
            }
            
        except Exception as e:
            self.logger.error(f"Error initiating SSO logout: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_sso_logout_response(self, saml_response: str) -> Dict[str, Any]:
        """Process SSO logout response"""
        try:
            # Process LogoutResponse
            response_result = self.saml_sp.process_logout_response(saml_response)
            
            if response_result['success']:
                self.logger.info("SSO logout completed successfully")
            else:
                self.logger.warning(f"SSO logout failed: {response_result['status_message']}")
            
            return response_result
            
        except Exception as e:
            self.logger.error(f"Error processing SSO logout response: {e}")
            return {
                'success': False,
                'error': str(e)
            }

# Example configuration and usage
if __name__ == "__main__":
    # Example SAML configuration (these would come from your IDP)
    saml_config = SAMLConfig(
        idp_entity_id="https://idp.example.com/saml",
        idp_sso_url="https://idp.example.com/saml/sso",
        idp_slo_url="https://idp.example.com/saml/slo",
        idp_cert="""-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODI0MTIzNDU2WhcNMjcwODIyMTIzNDU2WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuZ8/+RkD2pY6J9Q3q7kX7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n
7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n
7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n
7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n
7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8n7H8nMA0GCSqGSIb3
DQEBCwUAA4IBAQAo1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
-----END CERTIFICATE-----""",
        sp_entity_id="https://reports.example.com/saml/metadata",
        sp_acs_url="https://reports.example.com/saml/acs",
        sp_slo_url="https://reports.example.com/saml/slo"
    )
    
    # Initialize SSO service
    sso_service = SAMLSingleSignOnService(saml_config)
    
    print("🔐 SAML Single Sign-On Service Demo")
    print("=" * 45)
    
    # Demo SSO login initiation
    print("\n1. Initiating SSO login...")
    login_result = sso_service.initiate_sso_login("/dashboard")
    
    if login_result['success']:
        print("✅ SSO login initiated successfully")
        print(f"   Redirect URL: {login_result['redirect_url'][:50]}...")
        print(f"   Request ID: {login_result['request_id']}")
    else:
        print(f"❌ SSO login initiation failed: {login_result['error']}")
    
    # Demo session validation (with fake session for demo)
    print("\n2. Validating session...")
    fake_session = "sess_demo123"
    validation_result = sso_service.validate_session(fake_session)
    
    if validation_result['valid']:
        print("✅ Session validation successful")
        print(f"   User ID: {validation_result['user_id']}")
    else:
        print(f"⚠️ Session validation result: {validation_result['error']}")
        print("   (Expected for demo session)")
    
    print("\n🎯 SAML SSO Service Demo Complete")
    print("This demonstrates the core functionality of the SAML SSO system.")
    print("In a production environment, this would integrate with:")
    print("  • Identity Provider (Okta, Azure AD, ADFS, etc.)")
    print("  • User database for user validation")
    print("  • Session management with Redis or database")
    print("  • Proper error handling and logging")
    print("  • Certificate validation and security measures")