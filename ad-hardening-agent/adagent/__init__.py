"""AD endpoint-hardening defensive agent.

A human-in-the-loop defensive security agent for Active Directory
environments. It ingests findings (ADRemedy audit output or a SharpHound
collection), reasons over them with the attack graph, and proposes
remediations that only execute after an explicit operator approval.
"""

__version__ = "0.1.0"
