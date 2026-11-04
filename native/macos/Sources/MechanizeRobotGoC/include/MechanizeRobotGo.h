#ifndef MECHANIZE_ROBOTGO_H
#define MECHANIZE_ROBOTGO_H
int MechanizeRobotGoMove(double x, double y);
/* Down: 0 posted, 1 unknown, 2 rejected before calling MouseDown. */
int MechanizeRobotGoDown(double x, double y);
int MechanizeRobotGoUp(void);
#endif
