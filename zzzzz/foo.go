package zzzzz

type Component struct {
	Meta Meta `component:"name=Orders"`

	Input  any `contract:"role=input,type=orders.Input"`
	Output any `contract:"role=output,type=orders.Output"`

	Selectors struct {
		Orders struct {
			OrderBy string `bind:"query,in=order"`
		}
		OtherViewName struct {
			OrderBy string `bind:"query,in=x_order"`
			Fields  string `bind:"query,in=x_fields"`
		}
	}
}

type Meta struct {
	Route   Route   `route:"method=GET,path=/v1/orders"`
	Package Package `package:"default=github.com/acme/orders,alias=orders"`
	Imports struct {
		_ Import `package:"import=github.com/acme/common/types1,alias=common1"`
		_ Import `package:"import=github.com/acme/common/types2,alias=common2"`
		_ Import `package:"import=github.com/acme/common/types2,alias=common3"`
	}
}

type Route struct {
	Method string
	Path   string
}

type Package struct {
	DefaultPath  string
	DefaultAlias string
}

type Import struct {
	Path  string
	Alias string
}

type QuerySelector struct {
	Name       string   `selector:"name=default,ns=orders"`
	Projection bool     `selector:"projection=true"`
	Criteria   bool     `selector:"criteria=true"`
	OrderBy    bool     `selector:"orderby=true"`
	Limit      bool     `selector:"limit=true"`
	Offset     bool     `selector:"offset=true"`
	Page       bool     `selector:"page=true"`
	Filterable []string `selector:"filterable=id,status,createdAt"`
}

type Input struct {
	UserID int64     `parameter:"kind=query,name=userId,required=true"`
	Fields []string  `parameter:"kind=query,name=_fields"`
	Has    *InputHas `setMarker:"true"`
}

type Output struct {
	Data any `parameter:"kind=output,name=data"`
}

type InputHas struct {
	UserID bool
	Fields bool
}
