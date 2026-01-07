from log_webapp.app import build_tree, _user_root
import json

# Get admin user root
admin_root = _user_root('admin')
print(f"Admin root: {admin_root}")
print(f"Admin root exists: {admin_root.exists()}")

# Build tree
tree = build_tree(admin_root)
print(f"Tree structure: {json.dumps(tree, indent=2)}")
