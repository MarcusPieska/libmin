//--------------------------------------------------
//
// giTextBox
// 
// Quanta Sciences (c) 2023
// Rama Hoetzlein
//
//--------------------------------------------------


#ifndef DEF_GI_TEXTBOX
    #define DEF_GI_TEXTBOX
    
    #include "g2_obj.h"
  
    namespace glib {

    class GXAPI g2TextBox : public g2Obj {
    public:      
        virtual uchar getType()     { return 't'; }
        virtual void UpdateLayout ( Vec4F p ); 
        virtual void SetProperty ( std::string key, std::string val );
        virtual void drawBackgrd ();
        virtual void drawBorder ();
        virtual void drawForegrd ();

        g2TextBox () {};

        std::string   m_text;
        Vec4F         m_textclr;

    };


    }

#endif
