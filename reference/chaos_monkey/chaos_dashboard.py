#!/usr/bin/env python3
"""
SD-WAN Chaos Monkey Web Server - Enhanced with Real-time Dashboard

This extends the original chaos monkey with a web-based dashboard for monitoring
chaos engineering tests in real-time. Includes WebSocket support for live updates.
"""

import json
import logging
import threading
import time
import queue
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import argparse

# Web server imports
from flask import Flask, render_template_string, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit
import webbrowser

# Import the original chaos monkey classes
from sdwan_chaos_monkey import (
    SDWANChaosMonkey, ChaosType, WANInterface, VRRPInstance,
    MixedChaosTarget, TestResult, ApplianceInfo, setup_logging,
    load_node_filter
)


@dataclass
class DashboardState:
    """Dashboard state management"""
    status: str = "idle"
    current_cycle: int = 0
    total_cycles: Optional[int] = None
    success_count: int = 0
    failure_count: int = 0
    total_targets: int = 0
    appliances: List[Dict] = field(default_factory=list)
    current_target: Optional[Dict] = None
    log_messages: List[str] = field(default_factory=list)
    test_results: List[TestResult] = field(default_factory=list)
    start_time: Optional[datetime] = None
    chaos_type: str = ""
    duration_min: int = 30
    duration_max: Optional[int] = None
    wait_between_cycles: int = 300

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return (self.success_count / total * 100) if total > 0 else 0.0
    
    @property
    def uptime(self) -> str:
        if not self.start_time:
            return "00:00:00"
        delta = datetime.now() - self.start_time
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def add_log_message(self, message: str, max_messages: int = 50):
        """Add a log message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        self.log_messages.append(formatted_message)
        
        # Keep only the most recent messages
        if len(self.log_messages) > max_messages:
            self.log_messages = self.log_messages[-max_messages:]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'status': self.status,
            'currentCycle': self.current_cycle,
            'totalCycles': self.total_cycles,
            'successCount': self.success_count,
            'failureCount': self.failure_count,
            'successRate': self.success_rate,
            'totalTargets': self.total_targets,
            'appliances': self.appliances,
            'currentTarget': self.current_target,
            'logMessages': self.log_messages[-20:],  # Last 20 messages for dashboard
            'uptime': self.uptime,
            'chaosType': self.chaos_type,
            'durationMin': self.duration_min,
            'durationMax': self.duration_max,
            'waitBetweenCycles': self.wait_between_cycles,
            'testResults': [self._serialize_test_result(r) for r in self.test_results[-10:]]  # Last 10 results
        }
    
    def _serialize_test_result(self, result: TestResult) -> Dict:
        """Serialize TestResult for JSON"""
        return {
            'cycle': result.cycle,
            'targetName': result.target_name,
            'applianceName': result.appliance_name,
            'chaosType': result.chaos_type.value,
            'success': result.success,
            'timestamp': result.timestamp.isoformat(),
            'duration': result.duration_seconds,
            'details': result.details
        }


class WebEnabledChaosMonkey(SDWANChaosMonkey):
    """Extended Chaos Monkey with web dashboard integration"""
    
    def __init__(self, *args, **kwargs):
        # Extract web-specific parameters
        self.enable_web = kwargs.pop('enable_web', False)
        self.web_port = kwargs.pop('web_port', 1666)
        self.auto_open_browser = kwargs.pop('auto_open_browser', True)
        
        super().__init__(*args, **kwargs)
        
        # Dashboard state
        self.dashboard_state = DashboardState()
        self.dashboard_state.chaos_type = self.chaos_type.value
        self.dashboard_state.duration_min = self.duration_min
        self.dashboard_state.duration_max = self.duration_max
        
        # Web server components
        self.app = None
        self.socketio = None
        self.web_thread = None
        self.message_queue = queue.Queue()
        
        if self.enable_web:
            self._setup_web_server()
    
    def _setup_web_server(self):
        """Setup Flask web server with SocketIO"""
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = 'chaos_monkey_secret_key_2024'
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        # Setup routes
        self._setup_routes()
        self._setup_socketio_events()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        @self.app.route('/')
        def dashboard():
            """Serve the main dashboard"""
            return render_template_string(self._get_dashboard_template())
        
        @self.app.route('/api/status')
        def api_status():
            """API endpoint for dashboard status"""
            return jsonify(self.dashboard_state.to_dict())
        
        @self.app.route('/api/start_test', methods=['POST'])
        def api_start_test():
            """API endpoint to start chaos tests"""
            data = request.get_json()
            cycles = data.get('cycles')
            wait_time = data.get('wait', 300)
            selection = data.get('selection', 'sequential')
            
            # Start chaos tests in background thread
            if self.dashboard_state.status in ['idle', 'completed', 'error']:
                test_thread = threading.Thread(
                    target=self._run_web_chaos_test,
                    args=(cycles, wait_time, selection),
                    daemon=True
                )
                test_thread.start()
                return jsonify({'status': 'started'})
            else:
                return jsonify({'status': 'already_running'}), 400
        
        @self.app.route('/api/stop_test', methods=['POST'])
        def api_stop_test():
            """API endpoint to stop chaos tests"""
            self.dashboard_state.status = 'stopping'
            self._emit_log("INFO - Chaos test stop requested by user")
            return jsonify({'status': 'stopping'})
    
    def _setup_socketio_events(self):
        """Setup SocketIO event handlers"""
        @self.socketio.on('connect')
        def handle_connect():
            emit('status_update', self.dashboard_state.to_dict())
            self._emit_log("INFO - Dashboard client connected")
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            self._emit_log("INFO - Dashboard client disconnected")
        
        @self.socketio.on('request_update')
        def handle_request_update():
            emit('status_update', self.dashboard_state.to_dict())
    
    def start_web_server(self):
        """Start the web server in a separate thread"""
        if not self.enable_web or self.web_thread:
            return
        
        self.web_thread = threading.Thread(
            target=self._run_web_server,
            daemon=True
        )
        self.web_thread.start()
        
        # Wait a moment for server to start
        time.sleep(2)
        
        if self.auto_open_browser:
            try:
                webbrowser.open(f'http://localhost:{self.web_port}')
                self._emit_log(f"INFO - Dashboard opened in browser: http://localhost:{self.web_port}")
            except Exception as e:
                self._emit_log(f"WARNING - Could not open browser: {e}")
        
        self._emit_log(f"INFO - Web dashboard available at http://localhost:{self.web_port}")
    
    def _run_web_server(self):
        """Run the Flask-SocketIO server"""
        try:
            self.socketio.run(
                self.app,
                host='0.0.0.0',
                port=self.web_port,
                debug=False,
                use_reloader=False,
                log_output=False
            )
        except Exception as e:
            self._emit_log(f"ERROR - Web server failed: {e}")
    
    def _run_web_chaos_test(self, cycles: Optional[int], wait_time: int, selection: str):
        """Run chaos tests with web dashboard integration"""
        try:
            self.dashboard_state.status = "discovering"
            self.dashboard_state.start_time = datetime.now()
            self.dashboard_state.total_cycles = cycles
            self._emit_log("INFO - Starting chaos engineering tests...")
            self._broadcast_update()
            
            # Discovery phase
            self._emit_log("INFO - Discovering chaos targets...")
            self.chaos_targets = self.discover_chaos_targets()
            
            if not self.chaos_targets:
                self._emit_log("ERROR - No chaos targets found!")
                self.dashboard_state.status = "error"
                self._broadcast_update()
                return
            
            # Update dashboard with discovered targets
            self.dashboard_state.total_targets = len(self.chaos_targets)
            self.dashboard_state.appliances = [
                {
                    'nepk': nepk,
                    'name': appliance.name,
                    'site': appliance.site,
                    'model': appliance.model
                }
                for nepk, appliance in self.appliances.items()
            ]
            
            self._emit_log(f"INFO - Found {len(self.chaos_targets)} chaos targets on {len(self.appliances)} appliances")
            self.dashboard_state.status = "running"
            self._broadcast_update()
            
            # Main chaos test loop
            cycle_count = 0
            while (cycles is None or cycle_count < cycles) and self.dashboard_state.status == "running":
                cycle_count += 1
                self.dashboard_state.current_cycle = cycle_count
                
                # Select target
                target = self._select_next_target("sequential")  # You can make this configurable
                
                # Update current target info
                self._update_current_target_info(target)
                self._emit_log(f"INFO - Cycle {cycle_count}: Testing {self._get_target_description(target)}")
                self._broadcast_update()
                
                # Run the chaos test
                result = self.run_single_chaos_test(target)
                result.cycle = cycle_count
                
                # Update results
                self.dashboard_state.test_results.append(result)
                if result.success:
                    self.dashboard_state.success_count += 1
                    self._emit_log(f"SUCCESS - {self._get_target_description(target)} recovered successfully")
                else:
                    self.dashboard_state.failure_count += 1
                    self._emit_log(f"FAILURE - {self._get_target_description(target)} failed to recover")
                
                # Update index for next cycle
                self.current_test_index = (self.current_test_index + 1) % len(self.chaos_targets)
                
                # Clear current target
                self.dashboard_state.current_target = None
                self._broadcast_update()
                
                # Wait between cycles (unless this is the last cycle)
                if (cycles is None or cycle_count < cycles) and self.dashboard_state.status == "running":
                    self._emit_log(f"INFO - Waiting {wait_time} seconds before next cycle...")
                    self._wait_with_web_updates(wait_time)
            
            # Test completion
            if self.dashboard_state.status == "running":
                self.dashboard_state.status = "completed"
                self._emit_log("INFO - All chaos tests completed successfully")
            elif self.dashboard_state.status == "stopping":
                self._emit_log("INFO - Chaos tests stopped by user")
                self.dashboard_state.status = "idle"

            self.dashboard_state.current_target = None
            self._broadcast_update()
            self._print_final_summary(self.dashboard_state.test_results)
            
        except Exception as e:
            self._emit_log(f"ERROR - Chaos test failed: {e}")
            self.dashboard_state.status = "error"
            self._broadcast_update()
    
    def _update_current_target_info(self, target):
        """Update current target information in dashboard state"""
        if isinstance(target, WANInterface):
            appliance = self.appliances[target.nepk]
            self.dashboard_state.current_target = {
                'name': target.display_name,
                'type': 'WAN Interface',
                'appliance': appliance.name,
                'interface': target.interface_name,
                'ip': target.ip_address
            }
        elif isinstance(target, VRRPInstance):
            self.dashboard_state.current_target = {
                'name': target.display_name,
                'type': 'VRRP',
                'appliance': target.appliance_name,
                'interface': target.interface_name,
                'vrid': target.vrid,
                'priority': target.current_priority
            }
    
    def _get_target_description(self, target) -> str:
        """Get human-readable target description"""
        if isinstance(target, WANInterface):
            appliance = self.appliances[target.nepk]
            return f"WAN Interface {target.display_name} on {appliance.name}"
        elif isinstance(target, VRRPInstance):
            return f"VRRP {target.display_name} on {target.appliance_name}"
        return str(target)
    
    def _wait_with_countdown(self, duration: int, chaos_description: str = "chaos"):
        """Override base class countdown to check for stop requests"""
        self._emit_log(f"INFO - Introducing {chaos_description} for {duration} seconds...")
        for remaining in range(duration, 0, -1):
            if self.dashboard_state.status != "running":
                self._emit_log(f"WARNING - {chaos_description} interrupted by stop request")
                break
            if remaining % 10 == 0 or remaining <= 5:
                self._emit_log(f"INFO - {remaining} seconds of {chaos_description} remaining...")
                self._broadcast_update()
            time.sleep(1)

    def _wait_with_web_updates(self, duration: int):
        """Wait with periodic web dashboard updates"""
        for remaining in range(duration, 0, -1):
            if self.dashboard_state.status != "running":
                break

            if remaining % 30 == 0 or remaining <= 10:
                self._emit_log(f"INFO - Next test in {remaining} seconds...")
                self._broadcast_update()

            time.sleep(1)

    def verify_interface_operational(self, wan_interface, max_wait: int = 60) -> bool:
        """Override base class to check for stop requests during verification"""
        appliance = self.appliances[wan_interface.nepk]
        self._emit_log(f"INFO - Verifying {wan_interface.display_name} is operational on {appliance.name}...")

        start_time = time.time()
        check_interval = 5

        while time.time() - start_time < max_wait:
            if self.dashboard_state.status != "running":
                self._emit_log("WARNING - Verification interrupted by stop request")
                return True  # Don't mark as failure on user stop
            status = self.get_interface_status(wan_interface.nepk, wan_interface.interface_name)
            if status:
                admin_status = status.get('admin', False)
                oper_status = status.get('oper', False)
                if admin_status and oper_status:
                    self._emit_log(f"INFO - Interface {wan_interface.display_name} is operational")
                    return True
                elif admin_status:
                    elapsed = int(time.time() - start_time)
                    self._emit_log(f"INFO - Interface admin UP, waiting for operational... ({elapsed}s)")
            time.sleep(check_interval)

        self._emit_log(f"WARNING - Interface {wan_interface.display_name} did not become operational within {max_wait}s")
        return False

    def _emit_log(self, message: str):
        """Emit log message to both logger and dashboard"""
        # Log level parsing
        if message.startswith("ERROR"):
            level = "ERROR"
            self.logger.error(message[8:])  # Remove "ERROR - " prefix
        elif message.startswith("WARNING"):
            level = "WARNING"
            self.logger.warning(message[10:])  # Remove "WARNING - " prefix
        elif message.startswith("SUCCESS"):
            level = "INFO"
            self.logger.info(message[10:])  # Remove "SUCCESS - " prefix
        else:
            level = "INFO"
            self.logger.info(message[7:] if message.startswith("INFO - ") else message)
        
        # Add to dashboard
        self.dashboard_state.add_log_message(message)
        
        # Emit to web clients if web server is running
        if self.socketio:
            self.socketio.emit('log_message', {'message': message, 'level': level})
    
    def _broadcast_update(self):
        """Broadcast state update to all connected clients"""
        if self.socketio:
            self.socketio.emit('status_update', self.dashboard_state.to_dict())
    
    def _get_dashboard_template(self) -> str:
        """Return the 12 Monkeys themed dashboard HTML template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NETWORK CHAOS PROTOCOL // 12 MONKEYS</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><circle cx='50' cy='50' r='45' fill='none' stroke='%238b0000' stroke-width='6'/><text y='.88em' x='.05em' font-size='75' fill='%238b0000'>&#9762;</text></svg>">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

        * { box-sizing: border-box; }

        body {
            font-family: 'Courier New', 'Share Tech Mono', monospace;
            background: #000;
            color: #d4d4d4;
            margin: 0;
            padding: 0;
        }

        .success-text { color: #22c55e; }
        .error-text { color: #dc2626; }
        .warning-text { color: #d97706; }
        .info-text { color: #4ade80; }

        /* Scanline overlay */
        .scanlines::after {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                rgba(0,0,0,0.15) 2px,
                rgba(0,0,0,0.15) 4px
            );
            pointer-events: none;
            z-index: 9999;
        }

        /* Glitch flicker on title */
        @keyframes glitch {
            0% { text-shadow: 2px 0 #dc2626, -2px 0 #8b0000; }
            20% { text-shadow: -2px 0 #dc2626, 2px 0 #8b0000; }
            40% { text-shadow: 2px 2px #dc2626, -2px -2px #8b0000; opacity: 0.95; }
            60% { text-shadow: -1px 0 #dc2626, 1px 0 #8b0000; }
            80% { text-shadow: 2px -1px #dc2626, -2px 1px #8b0000; opacity: 1; }
            100% { text-shadow: 2px 0 #dc2626, -2px 0 #8b0000; }
        }
        @keyframes flicker {
            0%, 100% { opacity: 1; }
            92% { opacity: 1; }
            93% { opacity: 0.7; }
            94% { opacity: 1; }
            96% { opacity: 0.6; }
            97% { opacity: 1; }
        }
        .glitch-title {
            animation: glitch 3s infinite, flicker 5s infinite;
            color: #dc2626;
            text-shadow: 2px 0 #8b0000, -2px 0 #8b0000;
            letter-spacing: 0.15em;
            text-transform: uppercase;
        }

        /* Pulsing biohazard indicator */
        @keyframes biohazard-pulse {
            0%, 100% { box-shadow: 0 0 5px #dc2626, 0 0 10px #8b0000; opacity: 1; }
            50% { box-shadow: 0 0 20px #dc2626, 0 0 40px #8b0000, 0 0 60px rgba(139,0,0,0.3); opacity: 0.8; }
        }
        .biohazard-active {
            animation: biohazard-pulse 1.5s ease-in-out infinite;
        }

        .pulse-dot {
            animation: biohazard-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }

        .chaos-animation {
            animation: shake 0.3s ease-in-out infinite alternate;
        }
        @keyframes shake {
            0% { transform: translateX(0px) rotate(0deg); }
            100% { transform: translateX(2px) rotate(1deg); }
        }

        /* Hazard stripe border */
        .hazard-border {
            border: 2px solid #dc2626;
            background-image: repeating-linear-gradient(
                -45deg,
                transparent,
                transparent 10px,
                rgba(139,0,0,0.2) 10px,
                rgba(139,0,0,0.2) 20px
            );
        }

        /* Dark panel styling */
        .dark-panel {
            background: #111;
            border: 1px solid #2a0000;
            transition: box-shadow 0.3s ease, border-color 0.3s ease;
        }
        .dark-panel:hover {
            border-color: #8b0000;
            box-shadow: 0 0 15px rgba(139,0,0,0.3);
        }

        /* Log terminal CRT effect */
        .crt-terminal {
            background: #0a0a0a;
            border: 1px solid #1a3a1a;
            position: relative;
            overflow: hidden;
        }
        .crt-terminal::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(
                0deg,
                transparent,
                transparent 1px,
                rgba(0,40,0,0.08) 1px,
                rgba(0,40,0,0.08) 2px
            );
            pointer-events: none;
        }

        .log-entry {
            transition: all 0.3s ease-in-out;
            font-size: 0.8rem;
            line-height: 1.4;
        }
        .log-entry.new {
            background-color: rgba(0, 200, 0, 0.08);
            border-left: 2px solid #22c55e;
        }

        /* Blinking cursor */
        @keyframes blink-cursor {
            0%, 100% { opacity: 1; }
            50% { opacity: 0; }
        }
        .blink-cursor::after {
            content: '\\25AE';
            color: #4ade80;
            animation: blink-cursor 1s step-end infinite;
        }

        /* Red glow on headings */
        .red-glow {
            text-shadow: 0 0 8px rgba(220,38,38,0.6), 0 0 20px rgba(139,0,0,0.3);
        }

        /* Buttons */
        .btn-initiate {
            background: #8b0000;
            color: #d4d4d4;
            border: 1px solid #dc2626;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-initiate:hover:not(:disabled) {
            background: #dc2626;
            box-shadow: 0 0 15px rgba(220,38,38,0.5);
            color: #fff;
        }
        .btn-initiate:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }
        .btn-abort {
            background: #1a1a1a;
            color: #d97706;
            border: 1px solid #d97706;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn-abort:hover:not(:disabled) {
            background: #d97706;
            color: #000;
            box-shadow: 0 0 15px rgba(217,119,6,0.5);
        }
        .btn-abort:disabled {
            opacity: 0.3;
            cursor: not-allowed;
        }

        /* Form inputs */
        .dark-input {
            background: #0a0a0a;
            border: 1px solid #333;
            color: #d4d4d4;
            font-family: 'Courier New', monospace;
            padding: 0.5rem 0.75rem;
            width: 100%;
        }
        .dark-input:focus {
            outline: none;
            border-color: #8b0000;
            box-shadow: 0 0 8px rgba(139,0,0,0.4);
        }

        .section-header {
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 0.2em;
            font-size: 0.75rem;
            color: #8b0000;
            border-bottom: 1px solid #2a0000;
            padding-bottom: 0.5rem;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body class="scanlines">
    <div class="min-h-screen">
        <!-- Header -->
        <div style="background: #0a0a0a; border-bottom: 2px solid #8b0000;">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex items-center justify-between h-20">
                    <div class="flex items-center space-x-4">
                        <div class="relative">
                            <div id="chaos-icon" class="w-14 h-14 flex items-center justify-center">
                                <svg viewBox="0 0 120 120" width="56" height="56" xmlns="http://www.w3.org/2000/svg">
                                    <circle cx="60" cy="60" r="54" fill="none" stroke="#8b0000" stroke-width="3"/>
                                    <circle cx="60" cy="60" r="48" fill="none" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="8 4"/>
                                    <!-- 12 monkey silhouettes in a circle -->
                                    <g fill="#dc2626">
                                        <circle cx="60" cy="14" r="5"/>
                                        <circle cx="83" cy="20" r="5"/>
                                        <circle cx="98" cy="39" r="5"/>
                                        <circle cx="103" cy="62" r="5"/>
                                        <circle cx="96" cy="84" r="5"/>
                                        <circle cx="80" cy="100" r="5"/>
                                        <circle cx="60" cy="106" r="5"/>
                                        <circle cx="40" cy="100" r="5"/>
                                        <circle cx="24" cy="84" r="5"/>
                                        <circle cx="17" cy="62" r="5"/>
                                        <circle cx="22" cy="39" r="5"/>
                                        <circle cx="37" cy="20" r="5"/>
                                    </g>
                                    <!-- Biohazard inner symbol -->
                                    <path d="M60 42 Q68 50 60 60 Q52 50 60 42Z" fill="#8b0000"/>
                                    <path d="M60 78 Q68 70 60 60 Q52 70 60 78Z" fill="#8b0000"/>
                                    <path d="M42 60 Q50 52 60 60 Q50 68 42 60Z" fill="#8b0000"/>
                                    <path d="M78 60 Q70 52 60 60 Q70 68 78 60Z" fill="#8b0000"/>
                                    <circle cx="60" cy="60" r="6" fill="#0a0a0a"/>
                                </svg>
                            </div>
                            <div id="status-indicator" class="absolute -top-1 -right-1 w-4 h-4 bg-gray-700 rounded-full" style="border: 1px solid #333;"></div>
                        </div>
                        <div>
                            <h1 class="text-xl font-bold glitch-title">NETWORK CHAOS PROTOCOL</h1>
                            <p class="text-xs" style="color: #555; letter-spacing: 0.3em; text-transform: uppercase;">THE ARMY OF THE TWELVE MONKEYS</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-6">
                        <div id="status-badge" class="inline-flex items-center px-3 py-1 text-sm font-mono uppercase" style="background: #1a1a1a; border: 1px solid #333; letter-spacing: 0.1em; color: #666;">
                            <span id="status">Idle</span>
                        </div>
                        <div class="text-right">
                            <div class="text-lg font-mono" id="uptime" style="color: #dc2626;">00:00:00</div>
                            <div class="text-xs" style="color: #555; text-transform: uppercase; letter-spacing: 0.15em;">Elapsed</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Control Panel -->
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
            <div class="dark-panel p-4 mb-6">
                <div class="flex items-center justify-between mb-3">
                    <div class="section-header" style="border-bottom: none; margin-bottom: 0; padding-bottom: 0;">COMMAND INTERFACE</div>
                    <div class="flex space-x-3">
                        <button id="start-btn" class="btn-initiate px-5 py-2">
                            INITIATE SEQUENCE
                        </button>
                        <button id="stop-btn" class="btn-abort px-5 py-2" disabled>
                            ABORT PROTOCOL
                        </button>
                    </div>
                </div>
                <div class="mt-3 grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label class="block text-xs uppercase mb-1" style="color: #666; letter-spacing: 0.15em;">Cycles</label>
                        <input id="cycles-input" type="number" placeholder="INFINITE" class="dark-input">
                    </div>
                    <div>
                        <label class="block text-xs uppercase mb-1" style="color: #666; letter-spacing: 0.15em;">Wait Interval (sec)</label>
                        <input id="wait-input" type="number" value="60" class="dark-input">
                    </div>
                    <div>
                        <label class="block text-xs uppercase mb-1" style="color: #666; letter-spacing: 0.15em;">Target Selection</label>
                        <select id="selection-input" class="dark-input">
                            <option value="sequential">SEQUENTIAL</option>
                            <option value="random">RANDOM</option>
                            <option value="weighted-random">WEIGHTED RANDOM</option>
                        </select>
                    </div>
                </div>
            </div>
        </div>

        <!-- Main Content -->
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <!-- Stats Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div class="dark-panel p-5" style="border-left: 3px solid #dc2626;">
                    <div class="section-header">CYCLE</div>
                    <p class="text-3xl font-mono font-bold" id="cycle" style="color: #dc2626;">0</p>
                    <p class="text-xs mt-1" id="cycle-info" style="color: #555;">Awaiting orders</p>
                </div>

                <div class="dark-panel p-5" style="border-left: 3px solid #d97706;">
                    <div class="section-header">EFFICACY RATE</div>
                    <p class="text-3xl font-mono font-bold" id="success" style="color: #d97706;">0.0%</p>
                    <p class="text-xs mt-1" id="success-info" style="color: #555;">0 confirmed / 0 dispatched</p>
                </div>

                <div class="dark-panel p-5" style="border-left: 3px solid #8b0000;">
                    <div class="section-header">TARGETS ACQUIRED</div>
                    <p class="text-3xl font-mono font-bold" id="targets" style="color: #8b0000;">0</p>
                    <p class="text-xs mt-1" id="chaos-type" style="color: #555;">WAN + VRRP vectors</p>
                </div>

                <div class="dark-panel p-5" style="border-left: 3px solid #555;">
                    <div class="section-header">NODES</div>
                    <p class="text-3xl font-mono font-bold" id="appliances" style="color: #d4d4d4;">0</p>
                    <p class="text-xs mt-1" style="color: #555;">Compromised devices</p>
                </div>
            </div>

            <!-- Current Target Section -->
            <div id="current-target-section" class="hazard-border p-5 mb-6" style="display: none; background: #111;">
                <div class="flex items-center justify-between mb-4">
                    <div class="section-header red-glow" style="border-bottom: none; margin-bottom: 0; padding-bottom: 0; color: #dc2626; font-size: 0.85rem;">ACTIVE CHAOS VECTOR</div>
                    <div class="w-3 h-3 bg-red-700 rounded-full biohazard-active chaos-animation"></div>
                </div>
                <div style="background: #0a0a0a; border: 1px solid #1a1a1a;" class="p-4">
                    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                        <div>
                            <p class="text-xs uppercase" style="color: #555; letter-spacing: 0.15em;">Target</p>
                            <p class="text-sm font-mono font-bold mt-1" id="current-target-name" style="color: #dc2626;">-</p>
                        </div>
                        <div>
                            <p class="text-xs uppercase" style="color: #555; letter-spacing: 0.15em;">Type</p>
                            <p class="text-sm font-mono font-bold mt-1" id="current-target-type" style="color: #d97706;">-</p>
                        </div>
                        <div>
                            <p class="text-xs uppercase" style="color: #555; letter-spacing: 0.15em;">Node</p>
                            <p class="text-sm font-mono font-bold mt-1" id="current-target-appliance" style="color: #d4d4d4;">-</p>
                        </div>
                        <div>
                            <p class="text-xs uppercase" style="color: #555; letter-spacing: 0.15em;">Interface</p>
                            <p class="text-sm font-mono font-bold mt-1" id="current-target-interface" style="color: #d4d4d4;">-</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Test Results Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
                <!-- Recent Test Results -->
                <div class="dark-panel p-5">
                    <div class="section-header">OPERATION LOG</div>
                    <div id="test-results" class="space-y-2 max-h-64 overflow-y-auto">
                        <div class="text-xs text-center py-8" style="color: #444;">NO OPERATIONS RECORDED</div>
                    </div>
                </div>

                <!-- Appliances Overview -->
                <div class="dark-panel p-5">
                    <div class="section-header">NODE MANIFEST</div>
                    <div id="appliances-list" class="space-y-2 max-h-64 overflow-y-auto">
                        <div class="text-xs text-center py-8" style="color: #444;">NO NODES DISCOVERED</div>
                    </div>
                </div>
            </div>

            <!-- Transmission Log -->
            <div class="dark-panel p-5" style="border-color: #1a3a1a;">
                <div class="flex items-center justify-between mb-4">
                    <div class="section-header" style="border-bottom: none; margin-bottom: 0; padding-bottom: 0; color: #4ade80;">TRANSMISSION LOG</div>
                    <div class="flex items-center space-x-2">
                        <div id="log-indicator" class="w-2 h-2 rounded-full" style="background: #444;"></div>
                        <span class="text-xs uppercase" style="color: #4ade80; letter-spacing: 0.15em;">Signal</span>
                    </div>
                </div>
                <div class="crt-terminal p-4 font-mono text-sm max-h-64 overflow-y-auto">
                    <div id="log-messages" class="space-y-1 blink-cursor">
                        <div class="text-green-500 opacity-75" style="font-size: 0.8rem;">[00:00:00] SYS &gt; CHAOS PROTOCOL INTERFACE INITIALIZED</div>
                        <div class="text-green-500 opacity-75" style="font-size: 0.8rem;">[00:00:01] SYS &gt; 12 MONKEYS NETWORK CHAOS ENGINE ONLINE</div>
                        <div class="text-green-500 opacity-75" style="font-size: 0.8rem;">[00:00:02] SYS &gt; AWAITING ORDERS... INITIATE WHEN READY</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div style="background: #0a0a0a; border-top: 1px solid #1a0000;" class="mt-12">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-3">
                        <svg viewBox="0 0 120 120" width="24" height="24" xmlns="http://www.w3.org/2000/svg">
                            <circle cx="60" cy="60" r="54" fill="none" stroke="#8b0000" stroke-width="3"/>
                            <g fill="#8b0000">
                                <circle cx="60" cy="14" r="4"/><circle cx="83" cy="20" r="4"/>
                                <circle cx="98" cy="39" r="4"/><circle cx="103" cy="62" r="4"/>
                                <circle cx="96" cy="84" r="4"/><circle cx="80" cy="100" r="4"/>
                                <circle cx="60" cy="106" r="4"/><circle cx="40" cy="100" r="4"/>
                                <circle cx="24" cy="84" r="4"/><circle cx="17" cy="62" r="4"/>
                                <circle cx="22" cy="39" r="4"/><circle cx="37" cy="20" r="4"/>
                            </g>
                        </svg>
                        <div>
                            <p class="text-xs uppercase" style="color: #555; letter-spacing: 0.2em;">THE ARMY OF THE TWELVE MONKEYS</p>
                            <p class="text-xs" style="color: #333;">Network Chaos Protocol v2.0 // We were here before the machines</p>
                        </div>
                    </div>
                    <div class="flex items-center space-x-4">
                        <span class="text-xs font-mono" id="connection-status" style="color: #555;">SIGNAL ACTIVE</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // WebSocket connection
        const socket = io();
        
        // UI Elements
        const elements = {
            status: document.getElementById('status'),
            statusBadge: document.getElementById('status-badge'),
            statusIndicator: document.getElementById('status-indicator'),
            chaosIcon: document.getElementById('chaos-icon'),
            logIndicator: document.getElementById('log-indicator'),
            cycle: document.getElementById('cycle'),
            cycleInfo: document.getElementById('cycle-info'),
            success: document.getElementById('success'),
            successInfo: document.getElementById('success-info'),
            targets: document.getElementById('targets'),
            chaosType: document.getElementById('chaos-type'),
            appliances: document.getElementById('appliances'),
            uptime: document.getElementById('uptime'),
            currentTargetSection: document.getElementById('current-target-section'),
            currentTargetName: document.getElementById('current-target-name'),
            currentTargetType: document.getElementById('current-target-type'),
            currentTargetAppliance: document.getElementById('current-target-appliance'),
            currentTargetInterface: document.getElementById('current-target-interface'),
            logMessages: document.getElementById('log-messages'),
            testResults: document.getElementById('test-results'),
            appliancesList: document.getElementById('appliances-list'),
            connectionStatus: document.getElementById('connection-status'),
            startBtn: document.getElementById('start-btn'),
            stopBtn: document.getElementById('stop-btn'),
            cyclesInput: document.getElementById('cycles-input'),
            waitInput: document.getElementById('wait-input'),
            selectionInput: document.getElementById('selection-input')
        };
        
        // State management
        let currentData = {};
        let isConnected = false;
        
        // Socket event handlers
        socket.on('connect', () => {
            isConnected = true;
            elements.connectionStatus.textContent = 'SIGNAL ACTIVE';
            elements.connectionStatus.style.color = '#4ade80';
            elements.logIndicator.className = 'w-2 h-2 rounded-full pulse-dot';
            elements.logIndicator.style.background = '#4ade80';
            console.log('Connected to chaos monkey server');
        });

        socket.on('disconnect', () => {
            isConnected = false;
            elements.connectionStatus.textContent = 'SIGNAL LOST';
            elements.connectionStatus.style.color = '#dc2626';
            elements.logIndicator.className = 'w-2 h-2 rounded-full';
            elements.logIndicator.style.background = '#dc2626';
            console.log('Disconnected from chaos monkey server');
        });
        
        socket.on('status_update', (data) => {
            currentData = data;
            updateDashboard(data);
        });
        
        socket.on('log_message', (data) => {
            addLogMessage(data.message, data.level);
        });
        
        // Control handlers
        elements.startBtn.addEventListener('click', () => {
            const cycles = elements.cyclesInput.value ? parseInt(elements.cyclesInput.value) : null;
            const wait = parseInt(elements.waitInput.value) || 300;
            const selection = elements.selectionInput.value;
            
            fetch('/api/start_test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cycles, wait, selection })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'started') {
                    elements.startBtn.disabled = true;
                    elements.stopBtn.disabled = false;
                } else {
                    alert('Test already running or failed to start');
                }
            })
            .catch(error => {
                console.error('Error starting test:', error);
                alert('Failed to start test');
            });
        });
        
        elements.stopBtn.addEventListener('click', () => {
            fetch('/api/stop_test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(response => response.json())
            .then(data => {
                console.log('Stop request sent');
            })
            .catch(error => {
                console.error('Error stopping test:', error);
            });
        });
        
        // Update functions
        function updateDashboard(data) {
            updateStatus(data.status);
            updateStats(data);
            updateCurrentTarget(data.currentTarget);
            updateTestResults(data.testResults || []);
            updateAppliancesList(data.appliances || []);
            updateLogMessages(data.logMessages || []);
            
            // Update uptime
            elements.uptime.textContent = data.uptime || '00:00:00';
            
            // Update chaos type
            elements.chaosType.textContent = data.chaosType ? `${data.chaosType.toUpperCase()} vectors` : 'WAN + VRRP vectors';
        }
        
        function updateStatus(status) {
            elements.status.textContent = status.toUpperCase();

            // Reset base styles
            const badgeBase = 'inline-flex items-center px-3 py-1 text-sm font-mono uppercase';
            elements.statusBadge.className = badgeBase;
            elements.statusBadge.style.cssText = 'letter-spacing:0.1em;';
            elements.statusIndicator.className = 'absolute -top-1 -right-1 w-4 h-4 rounded-full';
            elements.statusIndicator.style.cssText = 'border:1px solid #333;';

            switch(status) {
                case 'running':
                    elements.statusBadge.style.cssText += 'background:#1a0000;border:1px solid #dc2626;color:#dc2626;';
                    elements.statusIndicator.style.cssText += 'background:#dc2626;';
                    elements.statusIndicator.classList.add('biohazard-active');
                    elements.chaosIcon.classList.add('chaos-animation');
                    elements.startBtn.disabled = true;
                    elements.stopBtn.disabled = false;
                    break;
                case 'discovering':
                    elements.statusBadge.style.cssText += 'background:#1a1a00;border:1px solid #d97706;color:#d97706;';
                    elements.statusIndicator.style.cssText += 'background:#d97706;';
                    elements.statusIndicator.classList.add('biohazard-active');
                    elements.startBtn.disabled = true;
                    elements.stopBtn.disabled = false;
                    break;
                case 'error':
                    elements.statusBadge.style.cssText += 'background:#1a0000;border:1px solid #dc2626;color:#dc2626;';
                    elements.statusIndicator.style.cssText += 'background:#dc2626;';
                    elements.chaosIcon.classList.remove('chaos-animation');
                    elements.startBtn.disabled = false;
                    elements.stopBtn.disabled = true;
                    break;
                case 'completed':
                    elements.statusBadge.style.cssText += 'background:#001a00;border:1px solid #22c55e;color:#22c55e;';
                    elements.statusIndicator.style.cssText += 'background:#22c55e;';
                    elements.chaosIcon.classList.remove('chaos-animation');
                    elements.startBtn.disabled = false;
                    elements.stopBtn.disabled = true;
                    break;
                case 'stopping':
                    elements.statusBadge.style.cssText += 'background:#1a1a00;border:1px solid #d97706;color:#d97706;';
                    elements.statusIndicator.style.cssText += 'background:#d97706;';
                    elements.chaosIcon.classList.remove('chaos-animation');
                    elements.startBtn.disabled = true;
                    elements.stopBtn.disabled = true;
                    break;
                default:
                    elements.statusBadge.style.cssText += 'background:#1a1a1a;border:1px solid #333;color:#666;';
                    elements.statusIndicator.style.cssText += 'background:#333;';
                    elements.chaosIcon.classList.remove('chaos-animation');
                    elements.startBtn.disabled = false;
                    elements.stopBtn.disabled = true;
            }
        }
        
        function updateStats(data) {
            elements.cycle.textContent = data.currentCycle || 0;
            elements.success.textContent = `${data.successRate?.toFixed(1) || 0.0}%`;
            elements.targets.textContent = data.totalTargets || 0;
            elements.appliances.textContent = data.appliances?.length || 0;
            
            // Update cycle info
            if (data.totalCycles) {
                elements.cycleInfo.textContent = `of ${data.totalCycles} programmed`;
            } else if (data.currentCycle > 0) {
                elements.cycleInfo.textContent = 'perpetual mode';
            } else {
                elements.cycleInfo.textContent = 'awaiting orders';
            }
            
            // Update success info
            const total = (data.successCount || 0) + (data.failureCount || 0);
            elements.successInfo.textContent = `${data.successCount || 0} confirmed / ${total} dispatched`;
        }
        
        function updateCurrentTarget(target) {
            if (target) {
                elements.currentTargetSection.style.display = 'block';
                elements.currentTargetName.textContent = target.name || '-';
                elements.currentTargetType.textContent = target.type || '-';
                elements.currentTargetAppliance.textContent = target.appliance || '-';
                elements.currentTargetInterface.textContent = target.interface || '-';
            } else {
                elements.currentTargetSection.style.display = 'none';
            }
        }
        
        function updateTestResults(results) {
            if (results.length === 0) {
                elements.testResults.innerHTML = '<div class="text-xs text-center py-8" style="color:#444;">NO OPERATIONS RECORDED</div>';
                return;
            }

            elements.testResults.innerHTML = results.slice(-10).reverse().map(result => {
                const statusColor = result.success ? '#22c55e' : '#dc2626';
                const statusLabel = result.success ? 'CONFIRMED' : 'FAILED';
                const statusIcon = result.success ? '&#9654;' : '&#9632;';
                const timestamp = new Date(result.timestamp).toLocaleTimeString();

                return `
                    <div class="flex items-center justify-between p-3" style="background:#0a0a0a;border:1px solid #1a1a1a;">
                        <div class="flex items-center space-x-3">
                            <span style="color:${statusColor};font-size:0.75rem;">${statusIcon}</span>
                            <div>
                                <p class="font-mono text-xs font-bold" style="color:#d4d4d4;">CYCLE ${result.cycle}</p>
                                <p class="text-xs" style="color:#555;">${result.targetName} // ${result.applianceName}</p>
                            </div>
                        </div>
                        <div class="text-right">
                            <p class="text-xs font-mono font-bold" style="color:${statusColor};">${statusLabel}</p>
                            <p class="text-xs" style="color:#444;">${timestamp}</p>
                        </div>
                    </div>
                `;
            }).join('');
        }
        
        function updateAppliancesList(appliances) {
            if (appliances.length === 0) {
                elements.appliancesList.innerHTML = '<div class="text-xs text-center py-8" style="color:#444;">NO NODES DISCOVERED</div>';
                return;
            }

            elements.appliancesList.innerHTML = appliances.map(appliance => `
                <div class="flex items-center justify-between p-3" style="background:#0a0a0a;border:1px solid #1a1a1a;">
                    <div class="flex items-center space-x-3">
                        <div class="w-2 h-2 rounded-full" style="background:#8b0000;box-shadow:0 0 6px #8b0000;"></div>
                        <div>
                            <p class="font-mono text-xs font-bold" style="color:#d4d4d4;">${appliance.name}</p>
                            <p class="text-xs" style="color:#555;">NEPK: ${appliance.nepk}</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <p class="text-xs" style="color:#666;">${appliance.site}</p>
                        <p class="text-xs" style="color:#444;">${appliance.model}</p>
                    </div>
                </div>
            `).join('');
        }
        
        function updateLogMessages(messages) {
            const container = elements.logMessages;
            container.innerHTML = messages.map(message => {
                const level = getLogLevel(message);
                const colorClass = getLogColor(level);
                return `<div class="log-entry ${colorClass}">${escapeHtml(message)}</div>`;
            }).join('');
            
            // Auto-scroll to bottom
            container.scrollTop = container.scrollHeight;
        }
        
        function addLogMessage(message, level) {
            const container = elements.logMessages;
            const div = document.createElement('div');
            div.className = `log-entry new ${getLogColor(level)}`;
            div.textContent = message;
            
            container.appendChild(div);
            
            // Remove 'new' class after animation
            setTimeout(() => div.classList.remove('new'), 3000);
            
            // Keep only last 50 messages
            while (container.children.length > 50) {
                container.removeChild(container.firstChild);
            }
            
            // Auto-scroll to bottom
            container.scrollTop = container.scrollHeight;
        }
        
        function getLogLevel(message) {
            if (message.includes('ERROR')) return 'ERROR';
            if (message.includes('WARNING')) return 'WARNING';
            if (message.includes('SUCCESS')) return 'SUCCESS';
            return 'INFO';
        }
        
        function getLogColor(level) {
            switch(level) {
                case 'ERROR': return 'error-text';
                case 'WARNING': return 'warning-text';
                case 'SUCCESS': return 'success-text';
                default: return 'info-text';  // green on CRT
            }
        }
        
        function capitalizeFirst(str) {
            return str.charAt(0).toUpperCase() + str.slice(1);
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Initial status request
        if (isConnected) {
            socket.emit('request_update');
        }
        
        // Fallback polling for status updates
        setInterval(() => {
            if (!isConnected) {
                fetch('/api/status')
                    .then(response => response.json())
                    .then(data => updateDashboard(data))
                    .catch(error => console.error('Failed to fetch status:', error));
            }
        }, 5000);
    </script>
</body>
</html>'''


def main():
    """Enhanced main function with web server support"""
    parser = argparse.ArgumentParser(
        description='SD-WAN Chaos Monkey with Web Dashboard',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with web dashboard (default behavior, port 1666)
  python3 chaos_dashboard.py --chaos-type wan-interface --token YOUR_TOKEN

  # Custom web port and no auto-browser opening
  python3 chaos_dashboard.py --chaos-type vrrp --token YOUR_TOKEN --web-port 8080 --no-browser

  # With random chaos duration and node filtering
  python3 chaos_dashboard.py --chaos-type all --token YOUR_TOKEN --duration-min 15 --duration-max 60 --nodes-file nodes.yaml

  # CLI-only mode (no web dashboard)
  python3 chaos_dashboard.py --chaos-type wan-interface --token YOUR_TOKEN --no-web --cycles 5
        """
    )

    # Chaos type
    parser.add_argument('--chaos-type', required=True, choices=['wan-interface', 'vrrp', 'all'],
                        help='Type of chaos to introduce')

    # Authentication
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument('--token', help='API token for authentication')
    auth_group.add_argument('--auth', help='Username:password for basic auth')

    # Orchestrator
    parser.add_argument('--url', default='https://jh-bgp-ha-sewan-orchsp-useast1.silverpeak.cloud',
                        help='Orchestrator base URL')
    parser.add_argument('--query-auth', action='store_true',
                        help='Use apiKey query parameter instead of X-Auth-Token header')

    # Chaos duration
    parser.add_argument('--duration-min', type=int, default=30,
                        help='Minimum (or fixed) chaos duration in seconds (default: 30)')
    parser.add_argument('--duration-max', type=int, default=None,
                        help='Maximum chaos duration in seconds (enables random duration)')

    # Node filtering
    parser.add_argument('--nodes-file', type=str, default=None,
                        help='Path to YAML file specifying nodes to include/exclude')

    # Test configuration
    parser.add_argument('--cycles', type=int, help='Number of chaos cycles (default: infinite)')
    parser.add_argument('--wait', type=int, default=300,
                        help='Wait time between cycles in seconds (default: 300)')
    parser.add_argument('--chaos-selection', choices=['sequential', 'random', 'weighted-random'],
                        default='sequential', help='Target selection strategy')

    # Randomization
    parser.add_argument('--randomize', action='store_true', default=True,
                        help='Randomize target order (default: enabled)')
    parser.add_argument('--no-randomize', action='store_true',
                        help='Disable randomization')
    parser.add_argument('--random-seed', type=int, help='Random seed for reproducible testing')

    # Web dashboard options
    parser.add_argument('--no-web', action='store_true',
                        help='Disable web dashboard (CLI-only mode)')
    parser.add_argument('--web-port', type=int, default=1666,
                        help='Web dashboard port (default: 1666)')
    parser.add_argument('--no-browser', action='store_true',
                        help="Don't auto-open browser")

    # Other options
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help='Disable SSL certificate verification')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    # Handle randomization flags
    if args.no_randomize:
        args.randomize = False

    setup_logging(args.debug)
    logger = logging.getLogger(__name__)

    try:
        # Parse authentication
        username = password = None
        if args.auth:
            if ':' not in args.auth:
                raise ValueError("Auth format should be username:password")
            username, password = args.auth.split(':', 1)

        # Create enhanced chaos monkey
        if args.chaos_type == 'wan-interface':
            chaos_type = ChaosType.WAN_INTERFACE
        elif args.chaos_type == 'vrrp':
            chaos_type = ChaosType.VRRP
        else:
            chaos_type = ChaosType.ALL

        node_filter = load_node_filter(args.nodes_file)

        chaos_monkey = WebEnabledChaosMonkey(
            base_url=args.url,
            chaos_type=chaos_type,
            auth_token=args.token,
            username=username,
            password=password,
            duration_min=args.duration_min,
            duration_max=args.duration_max,
            verify_ssl=not args.no_verify_ssl,
            use_query_auth=args.query_auth,
            randomize=args.randomize,
            random_seed=args.random_seed,
            node_filter=node_filter,
            enable_web=not args.no_web,
            web_port=args.web_port,
            auto_open_browser=not args.no_browser
        )

        if not args.no_web:
            # Web mode - start dashboard and wait
            logger.info("Starting in web dashboard mode...")
            chaos_monkey.start_web_server()

            try:
                # Keep the main thread alive
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Shutting down web dashboard...")
                return 0
        else:
            # Traditional CLI mode
            logger.info("Starting in CLI mode...")
            chaos_monkey.run_continuous_chaos_test(
                cycles=args.cycles,
                wait_between_cycles=args.wait,
                chaos_selection=args.chaos_selection
            )
            return 0

    except Exception as e:
        logger.error(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
