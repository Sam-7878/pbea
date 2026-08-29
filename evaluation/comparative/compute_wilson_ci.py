#!/usr/bin/env python3
import math

def wilson(successes: int, total: int, z: float = 1.959963984540054):
    if total == 0: return None
    p=successes/total; z2=z*z; d=1+z2/total
    c=(p+z2/(2*total))/d
    h=z*math.sqrt((p*(1-p)+z2/(4*total))/total)/d
    return max(0.0,c-h), min(1.0,c+h)
