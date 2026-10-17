# SentinelMesh Frontend Dashboard Specification

Version: 1.0
Project: SentinelMesh – Multi-Agent Collaborative Security System Using DPI

---

# Objective

Develop a modern web application that serves as the primary user interface for SentinelMesh.

The frontend is **NOT** intended to replace Grafana.

Instead, it should provide:

- Professional product interface
- Visualization of the multi-agent architecture
- Live agent monitoring
- Live event streaming
- Incident management
- Navigation to Grafana analytics

Grafana remains the monitoring and analytics backend.

---

# Design Philosophy

The UI should resemble a modern Security Operations Center (SOC).

Preferred characteristics:

- Dark theme
- Blue / Cyan accent colors
- Glassmorphism cards
- Smooth animations
- Responsive layout
- Enterprise appearance

Technology Stack

- Next.js 15
- React
- TypeScript
- Tailwind CSS
- shadcn/ui
- Lucide React
- Framer Motion
- Recharts (where needed)

---

# Application Structure

The application should contain the following pages.

## 1. Dashboard (Landing Page)

Purpose

Provide a high-level overview of the SentinelMesh platform.

Display:

- SentinelMesh logo
- Project title
- Subtitle

Example:

SentinelMesh

Multi-Agent Collaborative Security System Using DPI

System Status:
🟢 Operational

Display summary cards:

- Total Flows
- Total Detections
- Open Incidents
- Active Agents

Navigation cards:

- Live Monitoring
- Architecture
- Incidents
- Analytics

---

## 2. Architecture Page

This is the highlight of the application.

Display the entire multi-agent architecture visually.

Internet

↓

Sniffer Agent

↓

Kafka Broker

↓

DPI Agent

↓

Detection Agent

↓

Correlation Agent

↓

Response Agent

↓

Dashboard Writer

↓

PostgreSQL

↓

Grafana

Each component should appear as an interactive card.

Each card displays:

- Status
- Last heartbeat
- Messages processed
- Small activity indicator

Animated data flow between components.

Healthy agents glow green.

Offline agents glow red.

---

## 3. Agent Monitoring Page

Display every agent individually.

Each card contains:

Agent Name

Status

Heartbeat

Packets processed

Messages consumed

Messages produced

Uptime

Examples:

Sniffer Agent

Running

Packets Captured:
15281

Flows Generated:
2941

Kafka:
Connected

---

DPI Agent

Payloads inspected

Signatures matched

---

Detection Agent

Rules executed

Threats detected

---

Correlation Agent

Incidents created

---

Response Agent

Alerts generated

---

Dashboard Writer

Database writes

---

Coordinator

Heartbeats

Cluster health

---

## 4. Live Event Stream

Display a continuously updating timeline.

Example:

14:52:11

Packet Captured

↓

Flow Created

↓

Kafka Published

↓

DPI Inspection

↓

Detection Created

↓

Incident Correlated

↓

Stored in PostgreSQL

Newest events appear on top.

Support filtering by:

- Agent
- Severity
- Time

---

## 5. Incident Management

Display incidents in a professional table.

Columns:

Incident ID

Timestamp

Source IP

Destination IP

Attack Type

Severity

Status

Actions

Support:

Search

Sorting

Filtering

Severity colors:

Critical → Red

High → Orange

Medium → Yellow

Low → Blue

---

## 6. Monitoring Page

This page does NOT recreate Grafana.

Instead it should either

Embed Grafana

OR

Provide a button

Open Monitoring Dashboard

Grafana remains responsible for

- Metrics
- Time-series
- Analytics

---

## 7. Settings

Display

Docker Status

Kafka Status

Redis Status

PostgreSQL Status

Grafana Status

Prometheus Status

Environment information

Project version

---

# Navigation

Sidebar

Dashboard

Architecture

Agents

Events

Incidents

Monitoring

Settings

---

# Components

Reusable components should include

AgentCard

MetricCard

StatusBadge

ArchitectureNode

ArchitectureEdge

EventTimeline

IncidentTable

HealthIndicator

NavigationSidebar

TopBar

---

# Animations

Use Framer Motion.

Requirements

Fade-in cards

Animated connection lines

Pulsing health indicators

Smooth page transitions

Hover effects

Loading skeletons

---

# Color Scheme

Background

#0B1120

Cards

#111827

Primary

#2563EB

Success

#22C55E

Warning

#F59E0B

Danger

#EF4444

Text

#FFFFFF

Muted Text

#9CA3AF

---

# Icons

Use Lucide React.

Suggested icons:

Shield

Server

Database

Network

Activity

AlertTriangle

CheckCircle

RadioTower

Eye

Terminal

---

# Responsiveness

Desktop

Primary target.

Tablet

Fully supported.

Mobile

Basic support.

---

# Backend Integration

The frontend should consume existing backend APIs.

Do NOT change the existing backend architecture.

Do NOT modify Docker services.

Do NOT replace Grafana.

Do NOT replace PostgreSQL.

The frontend is purely a presentation layer.

---

# Deliverables

The implementation should include:

- Complete Next.js application
- Clean component architecture
- TypeScript throughout
- Responsive UI
- Professional SOC-style interface
- Easy integration with existing SentinelMesh backend

The final result should look like a commercial cybersecurity platform rather than a student project.