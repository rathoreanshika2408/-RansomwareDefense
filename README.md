#AI-Driven Android Ransomware Defense System

An intelligent Android security application that detects and prevents 
ransomware attacks in real-time using machine learning and behavioral analysis.

##Features
-  TensorFlow Lite ML model for threat classification
-  Real-time file entropy analysis
-  Honeypot file trap system
-  Live file system monitoring
-  Instant threat alerts & notifications
-  Risk scoring engine (0-100)
-  Threat history logging with Room database

##Architecture
- **Language:** Kotlin
- **UI:** Jetpack Compose
- **ML:** TensorFlow Lite
- **Database:** Room
- **Background:** Foreground Service + WorkManager

##How It Works
1. Monitors file system for suspicious activity
2. Analyzes file entropy to detect encryption
3. Uses honeypot files to trap ransomware
4. ML model classifies behavior as Normal/Suspicious/Ransomware
5. Risk score calculated and user alerted instantly

##Requirements
- Android 8.0+ (API 26)
- Storage permissions
