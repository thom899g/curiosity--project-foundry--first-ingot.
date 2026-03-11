"""
Foundry Scanner Core Engine
World-class smart contract analysis system with robust error handling and logging
"""
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import hashlib
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import requests
from web3 import Web3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('foundry_scanner.log')
    ]
)
logger = logging.getLogger(__name__)

class FoundryScanner:
    """Main scanner class with comprehensive error handling and Firebase integration"""
    
    def __init__(self, firebase_credentials_path: Optional[str] = None):
        """
        Initialize Foundry Scanner with Firebase integration
        
        Args:
            firebase_credentials_path: Path to Firebase service account JSON file
        """
        self.logger = logging.getLogger(f"{__name__}.FoundryScanner")
        self.w3 = None
        self.db = None
        self._initialized = False
        
        try:
            # Initialize Web3 with fallback providers
            providers = [
                'https://mainnet.infura.io/v3/',
                'https://rpc.ankr.com/eth',
                'https://cloudflare-eth.com'
            ]
            
            for provider_url in providers:
                try:
                    self.w3 = Web3(Web3.HTTPProvider(provider_url))
                    if self.w3.is_connected():
                        self.logger.info(f"Connected to Web3 provider: {provider_url}")
                        break
                except Exception as e:
                    self.logger.warning(f"Failed to connect to {provider_url}: {str(e)}")
            
            if not self.w3 or not self.w3.is_connected():
                raise ConnectionError("Could not connect to any Ethereum provider")
            
            # Initialize Firebase if credentials provided
            if firebase_credentials_path:
                self._initialize_firebase(firebase_credentials_path)
            
            self._initialized = True
            self.logger.info("Foundry Scanner initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Foundry Scanner: {str(e)}")
            raise
    
    def _initialize_firebase(self, credentials_path: str) -> None:
        """Initialize Firebase Admin SDK with proper error handling"""
        try:
            # Verify credentials file exists
            cred_path = Path(credentials_path)
            if not cred_path.exists():
                raise FileNotFoundError(f"Firebase credentials file not found: {credentials_path}")
            
            # Check if Firebase already initialized
            if not firebase_admin._apps:
                cred = credentials.Certificate(credentials_path)
                firebase_admin.initialize_app(cred)
                self.logger.info("Firebase Admin SDK initialized")
            
            self.db = firestore.client()
            self.logger.info("Firestore client initialized")
            
            # Test connection
            test_doc = self.db.collection('health_checks').document('scanner_init')
            test_doc.set({
                'timestamp': datetime.utcnow(),
                'status': 'healthy',
                'version': '1.0.0'
            })
            self.logger.debug("Firestore connection test successful")
            
        except Exception as e:
            self.logger.error(f"Firebase initialization failed: {str(e)}")
            raise
    
    def _run_slither(self, contract_path: str) -> Dict[str, Any]:
        """Execute Slither analysis with comprehensive error handling"""
        self.logger.info(f"Running Slither analysis on: {contract_path}")
        
        try:
            # Verify contract file exists
            contract_file = Path(contract_path)
            if not contract_file.exists():
                raise FileNotFoundError(f"Contract file not found: {contract_path}")
            
            # Construct command with timeout
            cmd = [
                'slither',
                contract_path,
                '--json',
                '-'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                check=True
            )
            
            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, 
                    cmd, 
                    result.stderr
                )
            
            # Parse JSON output
            analysis = json.loads(result.stdout)
            
            # Extract key metrics
            findings = {
                'detectors': [],
                'vulnerability_count': 0,
                'optimization_count': 0,
                'informational_count': 0
            }
            
            for detector in analysis.get('results', {}).get('detectors', []):
                finding = {
                    'check': detector.get('check', ''),
                    'impact': detector.get('impact', ''),
                    'confidence': detector.get('confidence', ''),
                    'description': detector.get('description', ''),
                    'elements': detector.get('elements', [])
                }
                
                findings['detectors'].append(finding)
                
                # Categorize by impact
                impact = detector.get('impact', '').lower()
                if impact in ['high', 'medium']:
                    findings['vulnerability_count'] += 1
                elif impact == 'optimization':
                    findings['optimization_count'] += 1
                elif impact == 'informational':
                    findings['informational_count'] += 1
            
            self.logger.info(f"Slither analysis complete: {findings['vulnerability_count']} vulnerabilities found")
            return findings
            
        except subprocess.TimeoutExpired:
            self.logger.error("Slither analysis timed out after 5 minutes")
            return {'error': 'Analysis timed out', 'detectors': []}
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Slither JSON output: {str(e)}")
            return {'error': 'Invalid JSON output', 'detectors': []}
        except Exception as e:
            self.logger.error(f"Slither analysis failed: {str(e)}")
            return {'error': str(e), 'detectors': []}
    
    def _run_mythril(self, contract_path: str) -> Dict[str, Any]:
        """Execute Mythril analysis with proper error handling"""
        self.logger.info(f"Running Mythril analysis on: {contract_path}")
        
        try:
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                tmp_path = tmp.name
            
            # Construct command
            cmd = [
                'myth',
                'analyze',
                contract_path,
                '--output',
                'json',
                '-o',
                tmp_path
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for Mythril
                check=False  # Don't raise on non-zero exit
            )
            
            # Read results if file was created
            if Path(tmp_path).exists():
                with open(tmp_path, 'r') as f:
                    analysis = json.load(f)
                Path(tmp_path).unlink()  # Clean up
            else:
                analysis = {'error': 'No output file generated'}
            
            # Parse results
            findings = {
                'issues': [],
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            if isinstance(analysis, dict):
                if 'issues' in analysis:
                    findings['issues'] = analysis['issues']
                elif 'error' in analysis:
                    findings['error'] = analysis['error']
            
            self.logger.info(f"Mythril analysis complete: {len(findings.get('issues', []))} issues found")
            return findings
            
        except Exception as e:
            self.logger.error(f"Mythril analysis failed: {str(e)}")
            return {
                'error': str(e),
                'issues': [],
                'success': False
            }
    
    def _calculate_security_score(self, slither_results: Dict, mythril_results: Dict) -> float:
        """Calculate comprehensive security score with weighted metrics"""
        try:
            score = 100.0  # Start with perfect score
            
            # Deduct for Slither vulnerabilities
            vuln_count = slither_results.get('vulnerability_count', 0)
            score -= vuln_count * 15  # Major deduction for vulnerabilities
            
            # Deduct for Mythril issues
            myth_issues = len(mythril_results.get('issues', []))
            score -= myth_issues * 10
            
            # Bonus for optimizations found
            opt_count = slither_results.get('optimization_count', 0)
            score += min(opt_count * 2, 10)  # Max 10 point bonus
            
            # Ensure score stays within bounds
            score = max(0.0, min(100.0, score))
            
            self.logger.info(f"Calculated security score: {score:.1f}/100")
            return score
            
        except Exception as e:
            self.logger.error(f"Score calculation failed: {str(e)}")
            return 50.0  # Default neutral score
    
    def _store_in_firestore(self, contract_hash: str, results: Dict) -> None:
        """Store analysis results in Firestore with error handling"""
        if not self.db:
            self.logger.warning("Firestore not initialized, skipping storage")
            return
        
        try:
            doc_ref = self.db.collection('public_scans').document(contract_hash)
            
            # Prepare document data
            doc_data = {
                'contract_hash': contract_hash,
                'results': results,
                'timestamp': firestore.SERVER_TIMESTAMP,
                'scanner_version': '1.0.0',
                'security_score': results.get('security_score', 0)
            }
            
            # Set with merge to update if exists
            doc_ref.set(doc_data, merge=True)
            self.logger.info(f"Results stored in Firestore for hash: {contract_hash}")
            
        except Exception as e:
            self.logger.error(f"Failed to store results in Firestore: {str(e)}")
    
    def run_standard_battery(self, contract_path: str, store_results: bool = True) -> Dict[str, Any]:
        """
        Execute complete security analysis battery
        
        Args:
            contract_path: Path to Solidity contract file
            store_results: Whether to store results in Firebase
            
        Returns:
            Dictionary containing all analysis results
        """
        if not self._initialized:
            raise RuntimeError("Scanner not properly initialized")
        
        self.logger.info(f"Starting standard analysis battery for: {contract_path}")
        
        try:
            # Calculate contract hash for tracking
            with open(contract_path, 'rb') as f:
                contract_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Run analyses
            slither_results = self._run_slither(contract_path)
            mythril_results = self._run_mythril(contract_path)
            
            # Calculate security score
            security_score = self._calculate_security_score(slither_results, mythril_results)
            
            # Compile final results
            results = {
                'contract_hash': contract_hash,
                'contract_path': contract_path,
                'slither': slither_results,
                'mythril': mythril_results,
                'security_score': security_score,
                'timestamp': datetime.utcnow().isoformat(),
                'risk_level': self._determine_risk_level(security_score)
            }
            
            # Store in Firestore if enabled
            if store_results and self.db:
                self._store_in_firestore(contract_hash, results)
            
            self.logger.info(f"Analysis complete. Security score: {security_score:.1f}")
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis battery failed: {str(e)}")
            raise
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on security score"""
        if score >= 90:
            return 'LOW'
        elif score >= 70:
            return 'MEDIUM'
        elif score >= 50:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def verify_deployed_contract(self, contract_address: str) -> Dict[str, Any]:
        """
        Verify if a deployed contract matches a previously analyzed hash
        
        Args:
            contract_address: Ethereum contract address
            
        Returns:
            Verification results
        """
        if not self.w3:
            raise RuntimeError("Web3 not initialized")
        
        try:
            # Validate address
            if not self.w3.is_address(contract_address):
                raise ValueError(f"Invalid Ethereum address: {contract_address}")
            
            checksum_address = self.w3.to_checksum_address(contract_address)
            
            # Get deployed bytecode
            bytecode = self.w3.eth.get_code(checksum_address).hex()
            if bytecode == '0x' or bytecode == '0x0':
                raise ValueError(f"No contract at address: {contract_address}")
            
            deployed_hash = hashlib.sha256(bytes.fromhex(bytecode[2:])).hexdigest()
            
            # Check if we have analysis for this