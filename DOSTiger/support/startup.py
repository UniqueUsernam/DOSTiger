from .targeting import DOSTarget
target = DOSTarget()
print("====== STARTING {} ATTACKS ON {} ======".format((target.Type.upper()), (target.addr.upper())))
target.multiattack()
