package usermanager

type Voidmanager struct{}

func (v *Voidmanager) AuthenticateUser(bytes []byte) (int64, int64, error) {
	return 0, 0, ErrMangerIsVoid
}

func (v *Voidmanager) AuthoriseNewSession(bytes []byte, info AuthorisationInfo) error {
	return ErrMangerIsVoid
}

func (v *Voidmanager) UploadStatus(updates []StatusUpdate) ([]StatusResponse, error) {
	return nil, ErrMangerIsVoid
}

func (v *Voidmanager) ListAllUsers() ([]UserInfo, error) {
	return []UserInfo{}, ErrMangerIsVoid
}

func (v *Voidmanager) GetUserInfo(UID []byte) (UserInfo, error) {
	return UserInfo{}, ErrMangerIsVoid
}

func (v *Voidmanager) WriteUserInfo(info UserInfo) error {
	return ErrMangerIsVoid
}

func (v *Voidmanager) DeleteUser(UID []byte) error {
	return ErrMangerIsVoid
}
