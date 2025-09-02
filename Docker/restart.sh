#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================="
echo -e "           FT_MALCOLM - Docker Restart Script       "
echo -e "=====================================================${NC}"
echo ""

echo -e "${YELLOW}[Info] Stopping all running containers...${NC}"
docker compose down

echo -e "${YELLOW}[Info] Removing ft_malcolm containers...${NC}"
docker rm -f $(docker ps -aq --filter "name=source" --filter "name=target" --filter "name=gateway") 2>/dev/null || true

echo -e "${YELLOW}[Info] Removing ft_malcolm images...${NC}"
docker rmi -f $(docker images --filter "reference=docker_*" -q) 2>/dev/null || true

echo -e "${YELLOW}[Info] Cleaning up unused Docker resources...${NC}"
docker system prune -f

echo ""
echo -e "${GREEN}[Info] Rebuilding and starting fresh containers...${NC}"
docker compose up --build -d

echo ""
echo -e "${GREEN}[Success] All containers restarted successfully!${NC}"
echo ""
echo -e "${WHITE}Container status:${NC}"
docker compose ps

echo ""
echo -e "${CYAN}====================================================="
echo -e "                   NEXT STEPS                       "
echo -e "=====================================================${NC}"
echo ""
echo -e "${YELLOW}1. Enter the source container:${NC}"
echo -e "   ${GREEN}docker exec -it source bash${NC}"
echo ""
echo -e "${YELLOW}2. Generate ft_malcolm commands:${NC}"
echo -e "   ${GREEN}./get_params.sh${NC}"
echo ""
echo -e "${YELLOW}3. Copy and execute the desired command${NC}"
echo ""
