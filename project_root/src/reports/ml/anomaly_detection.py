"""
ML-Based Anomaly Detection System for Enterprise Reporting System
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
import joblib
import json
import logging
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio
import aiohttp
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

@dataclass
class AnomalyDetectionConfig:
    """Configuration for anomaly detection system"""
    # Model settings
    model_type: str = "isolation_forest"  # isolation_forest, one_class_svm, dbscan, ensemble
    contamination: float = 0.1  # Expected proportion of anomalies (0.0 to 0.5)
    n_estimators: int = 100
    max_samples: Union[str, int] = "auto"
    bootstrap: bool = False
    
    # Feature engineering
    enable_feature_scaling: bool = True
    scaling_method: str = "standard"  # standard, minmax
    enable_feature_selection: bool = True
    feature_selection_threshold: float = 0.01
    
    # Training settings
    training_window_days: int = 30
    retrain_interval_hours: int = 24
    enable_online_learning: bool = True
    online_learning_batch_size: int = 1000
    
    # Detection settings
    detection_threshold: float = 0.5
    enable_ensemble_voting: bool = True
    ensemble_vote_threshold: float = 0.5
    
    # Performance settings
    enable_caching: bool = True
    cache_ttl_seconds: int = 3600
    enable_parallel_processing: bool = True
    max_concurrent_detections: int = 10
    
    # Alerting settings
    enable_alerting: bool = True
    alert_threshold: float = 0.7
    alert_cooldown_seconds: int = 300
    enable_slack_notifications: bool = False
    slack_webhook_url: Optional[str] = None
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_namespace: str = "reports_anomaly_detection"
    performance_threshold_ms: int = 1000
    
    # Model persistence
    model_save_path: str = "/tmp/anomaly_detection_model.pkl"
    enable_model_versioning: bool = True
    max_model_versions: int = 5

class AnomalyDetectionError(Exception):
    """Custom exception for anomaly detection errors"""
    pass

class FeatureExtractor:
    """Extract and engineer features from system metrics"""
    
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.scaler = None
        self.feature_names = []
        self.feature_importance = {}
    
    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """Extract features from raw system metrics"""
        try:
            # Ensure data is sorted by timestamp
            if 'timestamp' in data.columns:
                data = data.sort_values('timestamp')
            
            # Extract time-based features
            if 'timestamp' in data.columns:
                data['hour'] = pd.to_datetime(data['timestamp']).dt.hour
                data['day_of_week'] = pd.to_datetime(data['timestamp']).dt.dayofweek
                data['is_weekend'] = (data['day_of_week'] >= 5).astype(int)
            
            # Extract statistical features for time series data
            feature_columns = [col for col in data.columns if col not in ['timestamp', 'hostname', 'report_type']]
            
            engineered_features = data.copy()
            
            # Rolling window statistics
            for col in feature_columns:
                if col in data.columns and pd.api.types.is_numeric_dtype(data[col]):
                    # Rolling statistics
                    engineered_features[f'{col}_rolling_mean_5'] = data[col].rolling(window=5, min_periods=1).mean()
                    engineered_features[f'{col}_rolling_std_5'] = data[col].rolling(window=5, min_periods=1).std()
                    engineered_features[f'{col}_rolling_mean_10'] = data[col].rolling(window=10, min_periods=1).mean()
                    engineered_features[f'{col}_rolling_std_10'] = data[col].rolling(window=10, min_periods=1).std()
                    
                    # Rate of change
                    engineered_features[f'{col}_rate_of_change'] = data[col].diff().fillna(0)
                    engineered_features[f'{col}_acceleration'] = data[col].diff().diff().fillna(0)
                    
                    # Percentiles and quantiles
                    engineered_features[f'{col}_percentile_25'] = data[col].rolling(window=20, min_periods=1).quantile(0.25)
                    engineered_features[f'{col}_percentile_75'] = data[col].rolling(window=20, min_periods=1).quantile(0.75)
                    engineered_features[f'{col}_iqr'] = (
                        engineered_features[f'{col}_percentile_75'] - engineered_features[f'{col}_percentile_25']
                    )
                    
                    # Z-scores
                    engineered_features[f'{col}_z_score'] = (
                        (data[col] - data[col].mean()) / data[col].std()
                    ).fillna(0)
            
            # Cross-feature interactions
            numeric_columns = [col for col in feature_columns if pd.api.types.is_numeric_dtype(data[col])]
            for i, col1 in enumerate(numeric_columns):
                for col2 in numeric_columns[i+1:]:
                    if col1 in engineered_features.columns and col2 in engineered_features.columns:
                        engineered_features[f'{col1}_{col2}_ratio'] = (
                            engineered_features[col1] / (engineered_features[col2] + 1e-8)
                        )
                        engineered_features[f'{col1}_{col2}_difference'] = (
                            engineered_features[col1] - engineered_features[col2]
                        )
            
            # Store feature names
            self.feature_names = [col for col in engineered_features.columns if col not in ['timestamp', 'hostname', 'report_type']]
            
            return engineered_features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            raise AnomalyDetectionError(f"Feature extraction failed: {str(e)}")
    
    def scale_features(self, features: pd.DataFrame) -> np.ndarray:
        """Scale features for model training"""
        try:
            if not self.config.enable_feature_scaling:
                return features.values
            
            # Select only numeric features for scaling
            numeric_features = features.select_dtypes(include=[np.number])
            
            if self.scaler is None:
                if self.config.scaling_method == "standard":
                    self.scaler = StandardScaler()
                elif self.config.scaling_method == "minmax":
                    self.scaler = MinMaxScaler()
                else:
                    self.scaler = StandardScaler()
                
                # Fit scaler
                scaled_features = self.scaler.fit_transform(numeric_features)
            else:
                # Transform with existing scaler
                scaled_features = self.scaler.transform(numeric_features)
            
            return scaled_features
            
        except Exception as e:
            logger.error(f"Error scaling features: {e}")
            raise AnomalyDetectionError(f"Feature scaling failed: {str(e)}")
    
    def select_features(self, features: pd.DataFrame, target: Optional[np.ndarray] = None) -> pd.DataFrame:
        """Select most important features"""
        try:
            if not self.config.enable_feature_selection:
                return features
            
            # For unsupervised learning, use variance-based feature selection
            if target is None:
                # Remove low-variance features
                variances = features.var()
                selected_features = features.loc[:, variances > self.config.feature_selection_threshold]
                logger.info(f"Selected {len(selected_features.columns)} features based on variance")
                return selected_features
            else:
                # For supervised learning, use correlation-based selection
                correlations = {}
                for col in features.columns:
                    if pd.api.types.is_numeric_dtype(features[col]):
                        corr = abs(features[col].corr(pd.Series(target)))
                        correlations[col] = corr
                
                # Select top features
                sorted_features = sorted(correlations.items(), key=lambda x: x[1], reverse=True)
                top_features = [feat for feat, _ in sorted_features[:50]]  # Top 50 features
                
                selected_features = features[top_features]
                self.feature_importance = dict(sorted_features)
                
                logger.info(f"Selected {len(top_features)} features based on correlation")
                return selected_features
                
        except Exception as e:
            logger.error(f"Error selecting features: {e}")
            return features

class AnomalyDetector:
    """Main anomaly detection system with multiple algorithms"""
    
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.feature_extractor = FeatureExtractor(config)
        self.models = {}
        self.model_performance = {}
        self.alert_history = {}
        self.metrics = {
            'detections_run': 0,
            'anomalies_found': 0,
            'false_positives': 0,
            'model_training_runs': 0,
            'detection_timeouts': 0
        }
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize anomaly detection models"""
        try:
            if self.config.model_type == "isolation_forest":
                self.models['primary'] = IsolationForest(
                    contamination=self.config.contamination,
                    n_estimators=self.config.n_estimators,
                    max_samples=self.config.max_samples,
                    bootstrap=self.config.bootstrap,
                    random_state=42,
                    n_jobs=-1 if self.config.enable_parallel_processing else 1
                )
            elif self.config.model_type == "one_class_svm":
                self.models['primary'] = OneClassSVM(
                    nu=self.config.contamination,
                    kernel='rbf',
                    gamma='scale'
                )
            elif self.config.model_type == "dbscan":
                self.models['primary'] = DBSCAN(
                    eps=0.5,
                    min_samples=5,
                    n_jobs=-1 if self.config.enable_parallel_processing else 1
                )
            elif self.config.model_type == "ensemble":
                # Create ensemble of different models
                self.models['isolation_forest'] = IsolationForest(
                    contamination=self.config.contamination,
                    n_estimators=self.config.n_estimators,
                    random_state=42,
                    n_jobs=-1 if self.config.enable_parallel_processing else 1
                )
                self.models['one_class_svm'] = OneClassSVM(
                    nu=self.config.contamination,
                    kernel='rbf'
                )
            else:
                # Default to Isolation Forest
                self.models['primary'] = IsolationForest(
                    contamination=self.config.contamination,
                    n_estimators=self.config.n_estimators,
                    random_state=42
                )
            
            logger.info(f"Initialized {self.config.model_type} model(s)")
            
        except Exception as e:
            logger.error(f"Error initializing models: {e}")
            raise AnomalyDetectionError(f"Model initialization failed: {str(e)}")
    
    def train_model(self, training_data: pd.DataFrame, 
                   validation_data: Optional[pd.DataFrame] = None) -> Dict[str, float]:
        """Train anomaly detection model"""
        try:
            start_time = datetime.utcnow()
            
            # Extract features
            logger.info("Extracting features from training data...")
            features = self.feature_extractor.extract_features(training_data)
            
            # Scale features
            if self.config.enable_feature_scaling:
                logger.info("Scaling features...")
                scaled_features = self.feature_extractor.scale_features(features)
            else:
                scaled_features = features.values
            
            # Select features
            if self.config.enable_feature_selection:
                logger.info("Selecting important features...")
                selected_features = self.feature_extractor.select_features(
                    pd.DataFrame(scaled_features, columns=features.columns)
                )
                scaled_features = selected_features.values
            
            # Train models
            training_results = {}
            
            for model_name, model in self.models.items():
                logger.info(f"Training {model_name} model...")
                
                # Train model
                if hasattr(model, 'fit'):
                    model.fit(scaled_features)
                
                # Validate if validation data provided
                if validation_data is not None:
                    validation_score = self._validate_model(model, validation_data)
                    training_results[model_name] = validation_score
                    self.model_performance[model_name] = validation_score
                else:
                    training_results[model_name] = {'training_complete': True}
            
            # Update metrics
            self.metrics['model_training_runs'] += 1
            
            training_time = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"Model training completed in {training_time:.2f} seconds")
            
            # Save model
            self._save_model()
            
            return training_results
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            raise AnomalyDetectionError(f"Model training failed: {str(e)}")
    
    def _validate_model(self, model, validation_data: pd.DataFrame) -> Dict[str, float]:
        """Validate model performance"""
        try:
            # Extract and prepare validation features
            features = self.feature_extractor.extract_features(validation_data)
            
            if self.config.enable_feature_scaling:
                scaled_features = self.feature_extractor.scale_features(features)
            else:
                scaled_features = features.values
            
            # Get predictions
            if hasattr(model, 'predict'):
                predictions = model.predict(scaled_features)
                
                # Convert to anomaly scores (-1 for anomaly, 1 for normal)
                anomaly_scores = model.decision_function(scaled_features) if hasattr(model, 'decision_function') else None
                
                validation_score = {
                    'accuracy': np.mean(predictions == 1),  # Assuming most are normal
                    'anomaly_count': np.sum(predictions == -1),
                    'total_samples': len(predictions)
                }
                
                if anomaly_scores is not None:
                    validation_score['avg_anomaly_score'] = np.mean(anomaly_scores)
                    validation_score['min_anomaly_score'] = np.min(anomaly_scores)
                    validation_score['max_anomaly_score'] = np.max(anomaly_scores)
                
                return validation_score
            
            return {'validation_failed': True}
            
        except Exception as e:
            logger.error(f"Error validating model: {e}")
            return {'validation_error': str(e)}
    
    def detect_anomalies(self, data: pd.DataFrame, 
                        context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Detect anomalies in data"""
        try:
            start_time = datetime.utcnow()
            
            # Extract features
            features = self.feature_extractor.extract_features(data)
            
            # Scale features
            if self.config.enable_feature_scaling:
                scaled_features = self.feature_extractor.scale_features(features)
            else:
                scaled_features = features.values
            
            # Select features
            if self.config.enable_feature_selection:
                selected_features = self.feature_extractor.select_features(
                    pd.DataFrame(scaled_features, columns=features.columns)
                )
                scaled_features = selected_features.values
            
            # Detect anomalies
            anomalies = []
            
            if self.config.model_type == "ensemble" and self.config.enable_ensemble_voting:
                # Ensemble voting approach
                predictions = {}
                anomaly_scores = {}
                
                for model_name, model in self.models.items():
                    if hasattr(model, 'predict'):
                        pred = model.predict(scaled_features)
                        predictions[model_name] = pred
                        
                        if hasattr(model, 'decision_function'):
                            scores = model.decision_function(scaled_features)
                            anomaly_scores[model_name] = scores
                
                # Ensemble voting
                ensemble_predictions = self._ensemble_vote(predictions, anomaly_scores)
                anomalies = self._process_ensemble_results(
                    ensemble_predictions, data, features
                )
            else:
                # Single model approach
                model = self.models['primary']
                if hasattr(model, 'predict'):
                    predictions = model.predict(scaled_features)
                    anomaly_scores = model.decision_function(scaled_features) if hasattr(model, 'decision_function') else None
                    
                    anomalies = self._process_single_model_results(
                        predictions, anomaly_scores, data, features
                    )
            
            # Update metrics
            self.metrics['detections_run'] += 1
            self.metrics['anomalies_found'] += len([a for a in anomalies if a['is_anomaly']])
            
            detection_time = (datetime.utcnow() - start_time).total_seconds()
            if detection_time * 1000 > self.config.performance_threshold_ms:
                self.metrics['detection_timeouts'] += 1
                logger.warning(f"Slow anomaly detection: {detection_time:.2f}s")
            
            # Trigger alerts for high-confidence anomalies
            if self.config.enable_alerting:
                self._trigger_alerts(anomalies, context)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            raise AnomalyDetectionError(f"Anomaly detection failed: {str(e)}")
    
    def _ensemble_vote(self, predictions: Dict[str, np.ndarray], 
                      scores: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Perform ensemble voting"""
        try:
            # Combine predictions from all models
            num_models = len(predictions)
            combined_predictions = np.zeros(len(list(predictions.values())[0]))
            
            for model_name, pred in predictions.items():
                # Convert predictions to 0 (normal) and 1 (anomaly)
                binary_pred = (pred == -1).astype(int)
                combined_predictions += binary_pred
            
            # Calculate ensemble vote (fraction of models that flagged as anomaly)
            ensemble_votes = combined_predictions / num_models
            
            # Apply threshold
            final_predictions = (ensemble_votes >= self.config.ensemble_vote_threshold).astype(int)
            
            # Calculate average anomaly scores if available
            avg_scores = None
            if scores:
                score_arrays = list(scores.values())
                if score_arrays:
                    avg_scores = np.mean(score_arrays, axis=0)
            
            return {
                'predictions': final_predictions,
                'scores': avg_scores,
                'vote_fractions': ensemble_votes
            }
            
        except Exception as e:
            logger.error(f"Error in ensemble voting: {e}")
            # Fallback to first model
            first_model = list(predictions.keys())[0]
            return {
                'predictions': (predictions[first_model] == -1).astype(int),
                'scores': scores.get(first_model) if scores else None,
                'vote_fractions': None
            }
    
    def _process_ensemble_results(self, ensemble_results: Dict[str, np.ndarray], 
                                original_data: pd.DataFrame, 
                                features: pd.DataFrame) -> List[Dict[str, Any]]:
        """Process ensemble detection results"""
        try:
            predictions = ensemble_results['predictions']
            scores = ensemble_results.get('scores')
            vote_fractions = ensemble_results.get('vote_fractions')
            
            anomalies = []
            
            for i, (idx, row) in enumerate(original_data.iterrows()):
                is_anomaly = bool(predictions[i])
                confidence = float(vote_fractions[i]) if vote_fractions is not None else 0.0
                score = float(scores[i]) if scores is not None else 0.0
                
                # Determine severity based on confidence
                if confidence >= 0.8:
                    severity = 'critical'
                elif confidence >= 0.6:
                    severity = 'high'
                elif confidence >= 0.4:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                anomaly_result = {
                    'index': int(idx),
                    'is_anomaly': is_anomaly,
                    'confidence': confidence,
                    'anomaly_score': score,
                    'severity': severity,
                    'timestamp': row.get('timestamp', datetime.utcnow().isoformat()),
                    'hostname': row.get('hostname', 'unknown'),
                    'data_point': row.to_dict()
                }
                
                # Add feature importance if available
                if hasattr(self.feature_extractor, 'feature_importance'):
                    anomaly_result['feature_contributions'] = self._calculate_feature_contributions(
                        row, features.iloc[i] if i < len(features) else None
                    )
                
                anomalies.append(anomaly_result)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error processing ensemble results: {e}")
            return []
    
    def _process_single_model_results(self, predictions: np.ndarray, 
                                    scores: Optional[np.ndarray],
                                    original_data: pd.DataFrame,
                                    features: pd.DataFrame) -> List[Dict[str, Any]]:
        """Process single model detection results"""
        try:
            anomalies = []
            
            for i, (idx, row) in enumerate(original_data.iterrows()):
                is_anomaly = bool(predictions[i] == -1)  # -1 indicates anomaly in sklearn
                score = float(scores[i]) if scores is not None else 0.0
                confidence = abs(score)  # Use absolute score as confidence measure
                
                # Determine severity based on score
                if abs(score) >= 0.8:
                    severity = 'critical'
                elif abs(score) >= 0.6:
                    severity = 'high'
                elif abs(score) >= 0.4:
                    severity = 'medium'
                else:
                    severity = 'low'
                
                anomaly_result = {
                    'index': int(idx),
                    'is_anomaly': is_anomaly,
                    'confidence': confidence,
                    'anomaly_score': score,
                    'severity': severity,
                    'timestamp': row.get('timestamp', datetime.utcnow().isoformat()),
                    'hostname': row.get('hostname', 'unknown'),
                    'data_point': row.to_dict()
                }
                
                anomalies.append(anomaly_result)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error processing single model results: {e}")
            return []
    
    def _calculate_feature_contributions(self, original_row: pd.Series, 
                                       feature_row: Optional[pd.Series]) -> Dict[str, float]:
        """Calculate contribution of each feature to anomaly detection"""
        try:
            contributions = {}
            
            if feature_row is not None:
                # Simple approach: use feature values weighted by importance
                importance = getattr(self.feature_extractor, 'feature_importance', {})
                
                for feature_name in feature_row.index:
                    feature_value = feature_row[feature_name]
                    feature_weight = importance.get(feature_name, 0.1)  # Default weight
                    contributions[feature_name] = float(abs(feature_value) * feature_weight)
            
            return contributions
            
        except Exception as e:
            logger.debug(f"Error calculating feature contributions: {e}")
            return {}
    
    def _trigger_alerts(self, anomalies: List[Dict[str, Any]], 
                       context: Optional[Dict[str, Any]] = None):
        """Trigger alerts for detected anomalies"""
        try:
            if not self.config.enable_alerting:
                return
            
            high_confidence_anomalies = [
                anomaly for anomaly in anomalies 
                if anomaly['is_anomaly'] and anomaly['confidence'] >= self.config.alert_threshold
            ]
            
            if not high_confidence_anomalies:
                return
            
            # Check cooldown period
            current_time = datetime.utcnow()
            for anomaly in high_confidence_anomalies:
                hostname = anomaly['hostname']
                if hostname in self.alert_history:
                    last_alert_time = self.alert_history[hostname]
                    if (current_time - last_alert_time).total_seconds() < self.config.alert_cooldown_seconds:
                        continue  # Skip alert due to cooldown
                
                # Trigger alert
                self._send_alert(anomaly, context)
                self.alert_history[hostname] = current_time
            
        except Exception as e:
            logger.error(f"Error triggering alerts: {e}")
    
    def _send_alert(self, anomaly: Dict[str, Any], 
                   context: Optional[Dict[str, Any]] = None):
        """Send alert for detected anomaly"""
        try:
            alert_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'anomaly': anomaly,
                'context': context or {},
                'system': 'enterprise_reporting_anomaly_detection'
            }
            
            # Log alert
            logger.warning(f"ANOMALY DETECTED: {anomaly['hostname']} - "
                          f"Severity: {anomaly['severity']}, "
                          f"Confidence: {anomaly['confidence']:.2f}")
            
            # Send to Slack if configured
            if self.config.enable_slack_notifications and self.config.slack_webhook_url:
                asyncio.create_task(self._send_slack_alert(alert_data))
            
            # In a real implementation, you might also:
            # - Send email notifications
            # - Create tickets in issue tracking systems
            # - Trigger automated remediation workflows
            # - Send to SIEM systems
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def _send_slack_alert(self, alert_data: Dict[str, Any]):
        """Send alert to Slack webhook"""
        try:
            if not self.config.slack_webhook_url:
                return
            
            anomaly = alert_data['anomaly']
            
            slack_message = {
                "text": f"🚨 Anomaly Detected in Enterprise Reporting System",
                "attachments": [
                    {
                        "color": "danger",
                        "fields": [
                            {
                                "title": "Host",
                                "value": anomaly['hostname'],
                                "short": True
                            },
                            {
                                "title": "Severity",
                                "value": anomaly['severity'].upper(),
                                "short": True
                            },
                            {
                                "title": "Confidence",
                                "value": f"{anomaly['confidence']:.2f}",
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": anomaly['timestamp'],
                                "short": True
                            }
                        ],
                        "footer": "Enterprise Reporting System Anomaly Detection"
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.config.slack_webhook_url,
                    json=slack_message,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status != 200:
                        logger.error(f"Slack webhook failed with status: {response.status}")
            
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
    
    def _save_model(self):
        """Save trained model to disk"""
        try:
            if self.config.enable_model_versioning:
                # Save with timestamp for versioning
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                versioned_path = f"{self.config.model_save_path}.{timestamp}"
                joblib.dump(self.models, versioned_path)
                
                # Clean up old versions
                self._cleanup_old_models()
            else:
                # Save current model
                joblib.dump(self.models, self.config.model_save_path)
            
            logger.info(f"Model saved to {self.config.model_save_path}")
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def _cleanup_old_models(self):
        """Clean up old model versions"""
        try:
            import glob
            import os
            
            # Find all model files
            model_pattern = f"{self.config.model_save_path}.*"
            model_files = glob.glob(model_pattern)
            
            # Sort by timestamp and keep only recent versions
            if len(model_files) > self.config.max_model_versions:
                # Sort by modification time
                sorted_files = sorted(model_files, key=os.path.getmtime, reverse=True)
                
                # Remove old versions
                for old_file in sorted_files[self.config.max_model_versions:]:
                    try:
                        os.remove(old_file)
                        logger.info(f"Removed old model version: {old_file}")
                    except Exception as e:
                        logger.error(f"Error removing old model {old_file}: {e}")
            
        except Exception as e:
            logger.error(f"Error cleaning up old models: {e}")
    
    def load_model(self, model_path: Optional[str] = None):
        """Load trained model from disk"""
        try:
            path = model_path or self.config.model_save_path
            
            if os.path.exists(path):
                self.models = joblib.load(path)
                logger.info(f"Model loaded from {path}")
            else:
                logger.warning(f"Model file not found at {path}")
                
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise AnomalyDetectionError(f"Model loading failed: {str(e)}")
    
    def get_model_performance(self) -> Dict[str, Any]:
        """Get current model performance metrics"""
        try:
            return {
                'model_performance': self.model_performance.copy(),
                'metrics': self.metrics.copy(),
                'model_count': len(self.models),
                'model_types': list(self.models.keys()),
                'feature_count': len(getattr(self.feature_extractor, 'feature_names', [])),
                'last_training': getattr(self, '_last_training_time', 'never')
            }
            
        except Exception as e:
            logger.error(f"Error getting model performance: {e}")
            return {'error': str(e)}

class AnomalyDetectionService:
    """High-level service for anomaly detection with business logic"""
    
    def __init__(self, config: AnomalyDetectionConfig):
        self.config = config
        self.detector = AnomalyDetector(config)
        self.logger = logging.getLogger(__name__)
    
    async def analyze_system_metrics(self, metrics_data: pd.DataFrame, 
                                   system_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Analyze system metrics for anomalies"""
        try:
            start_time = datetime.utcnow()
            
            # Detect anomalies
            anomalies = self.detector.detect_anomalies(metrics_data, system_context)
            
            # Categorize anomalies by type
            categorized_anomalies = self._categorize_anomalies(anomalies)
            
            # Generate summary
            summary = self._generate_analysis_summary(anomalies, categorized_anomalies)
            
            analysis_time = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                'success': True,
                'anomalies': anomalies,
                'categorized_anomalies': categorized_anomalies,
                'summary': summary,
                'processing_time_seconds': analysis_time,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing system metrics: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _categorize_anomalies(self, anomalies: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize anomalies by type and severity"""
        try:
            categorized = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'normal': []
            }
            
            for anomaly in anomalies:
                severity = anomaly.get('severity', 'low')
                if severity in categorized:
                    categorized[severity].append(anomaly)
                else:
                    categorized['low'].append(anomaly)
            
            return categorized
            
        except Exception as e:
            self.logger.error(f"Error categorizing anomalies: {e}")
            return {'error': str(e)}
    
    def _generate_analysis_summary(self, anomalies: List[Dict[str, Any]], 
                                 categorized: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Generate analysis summary"""
        try:
            total_anomalies = len([a for a in anomalies if a.get('is_anomaly', False)])
            critical_anomalies = len(categorized.get('critical', []))
            high_anomalies = len(categorized.get('high', []))
            total_hosts = len(set(a.get('hostname', 'unknown') for a in anomalies))
            
            return {
                'total_anomalies': total_anomalies,
                'critical_anomalies': critical_anomalies,
                'high_anomalies': high_anomalies,
                'total_hosts_affected': total_hosts,
                'anomaly_rate': total_anomalies / len(anomalies) if anomalies else 0,
                'severity_distribution': {
                    severity: len(anomalies_list) 
                    for severity, anomalies_list in categorized.items()
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error generating analysis summary: {e}")
            return {'error': str(e)}

# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create anomaly detection configuration
    config = AnomalyDetectionConfig(
        model_type="isolation_forest",
        contamination=0.1,
        n_estimators=100,
        enable_feature_scaling=True,
        scaling_method="standard",
        enable_feature_selection=True,
        enable_alerting=True,
        alert_threshold=0.7,
        enable_metrics=True,
        metrics_namespace="reports_anomaly_demo"
    )
    
    print("🤖 ML-Based Anomaly Detection Demo")
    print("=" * 50)
    
    # Initialize anomaly detection service
    try:
        anomaly_service = AnomalyDetectionService(config)
        print("✅ Anomaly detection service initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize anomaly detection service: {e}")
        exit(1)
    
    # Create sample system metrics data
    print("\n1. Creating sample system metrics data...")
    try:
        # Generate synthetic system metrics data
        np.random.seed(42)
        timestamps = pd.date_range(start='2023-01-01', periods=1000, freq='5T')
        
        # Normal data
        normal_data = pd.DataFrame({
            'timestamp': timestamps[:-50],
            'hostname': [f'server-{i%10}' for i in range(950)],
            'cpu_usage_percent': np.random.normal(25, 10, 950),  # Mean 25%, std 10%
            'memory_usage_percent': np.random.normal(40, 15, 950),  # Mean 40%, std 15%
            'disk_usage_percent': np.random.normal(60, 20, 950),  # Mean 60%, std 20%
            'network_in_mbps': np.random.exponential(50, 950),  # Exponential distribution
            'network_out_mbps': np.random.exponential(30, 950),
            'process_count': np.random.poisson(100, 950),  # Poisson distribution
            'error_rate': np.random.exponential(0.01, 950)  # Low error rate
        })
        
        # Inject anomalies
        anomaly_data = pd.DataFrame({
            'timestamp': timestamps[-50:],
            'hostname': [f'anomaly-server-{i}' for i in range(50)],
            'cpu_usage_percent': np.random.normal(85, 5, 50),  # High CPU usage
            'memory_usage_percent': np.random.normal(90, 5, 50),  # High memory usage
            'disk_usage_percent': np.random.normal(95, 2, 50),  # Near full disk
            'network_in_mbps': np.random.exponential(500, 50),  # High network usage
            'network_out_mbps': np.random.exponential(300, 50),
            'process_count': np.random.poisson(500, 50),  # High process count
            'error_rate': np.random.exponential(0.5, 50)  # High error rate
        })
        
        # Combine normal and anomaly data
        sample_data = pd.concat([normal_data, anomaly_data], ignore_index=True)
        
        # Shuffle data
        sample_data = sample_data.sample(frac=1).reset_index(drop=True)
        
        print("✅ Sample data created successfully")
        print(f"   Total samples: {len(sample_data)}")
        print(f"   Anomalies injected: {len(anomaly_data)}")
        
    except Exception as e:
        print(f"❌ Failed to create sample data: {e}")
        exit(1)
    
    # Train model
    print("\n2. Training anomaly detection model...")
    try:
        # Split data for training and validation
        train_data = sample_data.iloc[:800]
        val_data = sample_data.iloc[800:]
        
        training_results = anomaly_service.detector.train_model(train_data, val_data)
        print("✅ Model training completed successfully")
        
        # Print training results
        for model_name, results in training_results.items():
            print(f"   {model_name}: {results}")
        
    except Exception as e:
        print(f"❌ Model training failed: {e}")
    
    # Detect anomalies
    print("\n3. Detecting anomalies in sample data...")
    try:
        # Analyze all data
        analysis_result = asyncio.run(
            anomaly_service.analyze_system_metrics(sample_data)
        )
        
        if analysis_result['success']:
            print("✅ Anomaly detection completed successfully")
            
            summary = analysis_result['summary']
            print(f"   Total anomalies detected: {summary['total_anomalies']}")
            print(f"   Critical anomalies: {summary['critical_anomalies']}")
            print(f"   High severity anomalies: {summary['high_anomalies']}")
            print(f"   Anomaly rate: {summary['anomaly_rate']:.2%}")
            
            # Show some detected anomalies
            anomalies = analysis_result['anomalies']
            high_severity_anomalies = [a for a in anomalies if a.get('severity') in ['critical', 'high']]
            
            print(f"\n   Sample high-severity anomalies:")
            for i, anomaly in enumerate(high_severity_anomalies[:5]):  # Show first 5
                data_point = anomaly.get('data_point', {})
                print(f"     {i+1}. Host: {anomaly.get('hostname', 'unknown')}")
                print(f"        Severity: {anomaly.get('severity', 'unknown').upper()}")
                print(f"        Confidence: {anomaly.get('confidence', 0):.2f}")
                print(f"        CPU: {data_point.get('cpu_usage_percent', 'N/A'):.1f}%")
                print(f"        Memory: {data_point.get('memory_usage_percent', 'N/A'):.1f}%")
                print()
        else:
            print(f"❌ Anomaly detection failed: {analysis_result['error']}")
        
    except Exception as e:
        print(f"❌ Anomaly detection failed: {e}")
    
    # Test model performance
    print("\n4. Testing model performance...")
    try:
        performance_stats = anomaly_service.detector.get_model_performance()
        print("✅ Model performance statistics retrieved")
        
        for key, value in performance_stats.items():
            print(f"   {key}: {value}")
        
    except Exception as e:
        print(f"❌ Failed to get model performance: {e}")
    
    print("\n🎯 ML-Based Anomaly Detection Demo Complete")
    print("This demonstrates the core functionality of the anomaly detection system.")
    print("In a production environment, this would integrate with:")
    print("  • Real-time streaming data sources")
    print("  • Advanced ML models with continuous learning")
    print("  • Comprehensive alerting and notification systems")
    print("  • Integration with incident response workflows")
    print("  • Detailed reporting and dashboard integration")
    print("  • Automated remediation capabilities")